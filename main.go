package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/pkg/errors"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/tuf"
)

type VerificationOptions struct {
	PredicateType *string
	Limit         *int    // hardcoded for fetching artifact
	OIDCIssuer    *string // hardcoded
	Subject       *string
}

type VerificationResult struct {
	Bundle *Bundle
	Result *verify.VerificationResult
	Desc   *v1.Descriptor
}

type Bundle struct {
	ProtoBundle   *bundle.ProtobufBundle
	DSSE_Envelope *in_toto.Statement
}

func main() {
	opts := VerificationOptions{}
	image := flag.String("image", "", "image used for verification")
	opts.PredicateType = flag.String("predicate-type", "", "filter bundles based on the predicate type")
	opts.Limit = flag.Int("limit", 100, "max number of attestations to fetch")
	opts.OIDCIssuer = flag.String("issuer", "https://token.actions.githubusercontent.com", "custom oidc issuer")
	opts.Subject = flag.String("subject", "", "identity of the issuer")

	flag.Parse()
	if len(os.Args) == 1 {
		fmt.Println("Usage: pass image with appropriate flags to verify images using github artifact attestations")
		flag.PrintDefaults()
	}

	ref, err := name.ParseReference(*image)
	if err != nil {
		panic(errors.Wrapf(err, "failed to parse image reference: %v", image))
	}

	bundles, desc, err := fetchBundles(ref, *opts.Limit, *opts.PredicateType)
	if err != nil {
		panic(err)
	}

	policy, err := buildPolicy(desc, opts)
	if err != nil {
		panic(err)
	}

	verifyOpts := buildVerifyOptions(opts)
	trustedMaterial, err := getTrustedRoot(context.TODO())
	if err != nil {
		panic(err)
	}

	results, err := verifyBundles(bundles, desc, trustedMaterial, policy, verifyOpts)
	if err != nil {
		panic(err)
	}

	val, err := json.MarshalIndent(results[0].Bundle.DSSE_Envelope, "", " ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(val))
}

func fetchBundles(ref name.Reference, limit int, predicateType string) ([]*Bundle, *v1.Descriptor, error) {
	bundles := make([]*Bundle, 0)

	remoteOpts := []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}

	desc, err := remote.Head(ref, remoteOpts...)
	if err != nil {
		return nil, nil, err
	}

	referrers, err := remote.Referrers(ref.Context().Digest(desc.Digest.String()), remoteOpts...)
	if err != nil {
		return nil, nil, err
	}

	referrersDescs, err := referrers.IndexManifest()
	if err != nil {
		return nil, nil, err
	}

	if len(referrersDescs.Manifests) > limit {
		return nil, nil, fmt.Errorf("failed to fetch referrers: to many referrers found, max limit is %d", limit)
	}

	for _, manifestDesc := range referrersDescs.Manifests {
		if !strings.HasPrefix(manifestDesc.ArtifactType, "application/vnd.dev.sigstore.bundle") {
			continue
		}

		refImg, err := remote.Image(ref.Context().Digest(manifestDesc.Digest.String()), remoteOpts...)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch referrer image: %w", err)
		}
		layers, err := refImg.Layers()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch referrer layer: %w", err)
		}
		layerBytes, err := layers[0].Uncompressed()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch referrer layer: %w", err)
		}
		bundleBytes, err := io.ReadAll(layerBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch referrer layer: %w", err)
		}
		b := &bundle.ProtobufBundle{}
		err = b.UnmarshalJSON(bundleBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal bundle: %w", err)
		}
		bundles = append(bundles, &Bundle{ProtoBundle: b})
	}

	if predicateType != "" {
		filteredBundles := make([]*Bundle, 0)
		for _, b := range bundles {
			dsseEnvelope := b.ProtoBundle.Bundle.GetDsseEnvelope()
			if dsseEnvelope != nil {
				if dsseEnvelope.PayloadType != "application/vnd.in-toto+json" {
					continue
				}
				var intotoStatement in_toto.Statement
				if err := json.Unmarshal([]byte(dsseEnvelope.Payload), &intotoStatement); err != nil {
					continue
				}

				if intotoStatement.PredicateType == predicateType {
					filteredBundles = append(filteredBundles, &Bundle{
						ProtoBundle:   b.ProtoBundle,
						DSSE_Envelope: &intotoStatement,
					})
				}
			}
		}
		return filteredBundles, desc, nil
	}

	return bundles, desc, nil
}

func buildPolicy(desc *v1.Descriptor, opts VerificationOptions) (verify.PolicyBuilder, error) {
	digest, err := hex.DecodeString(desc.Digest.Hex)
	if err != nil {
		return verify.PolicyBuilder{}, err
	}
	artifactDigestVerificationOption := verify.WithArtifactDigest(desc.Digest.Algorithm, digest)

	// TODO: Add full regexp support to sigstore and cosign
	// Verify images only has subject field, and no subject regexp, subject cannot be passed to subject regexp
	// because then string containing the subjects will also work. We should just add an issuer regexp
	// Solve this in a seperate PR,
	// See: https://github.com/sigstore/cosign/blob/7c20052077a81d667526af879ec40168899dde1f/pkg/cosign/verify.go#L339-L356
	subjectRegexp := ""
	if strings.Contains(*opts.Subject, "*") {
		subjectRegexp = *opts.Subject
		*opts.Subject = ""
	}
	id, err := verify.NewShortCertificateIdentity(*opts.OIDCIssuer, *opts.Subject, "", subjectRegexp)
	if err != nil {
		return verify.PolicyBuilder{}, err
	}
	return verify.NewPolicy(artifactDigestVerificationOption, verify.WithCertificateIdentity(id)), nil
}

func buildVerifyOptions(opts VerificationOptions) []verify.VerifierOption {
	var verifierOptions []verify.VerifierOption
	// if authority.RFC3161Timestamp != nil {
	// 	verifierOptions = append(verifierOptions, verify.WithSignedTimestamps(1))
	// } else {
	verifierOptions = append(verifierOptions, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	// }
	return verifierOptions
}

func getTrustedRoot(ctx context.Context) (*root.TrustedRoot, error) {
	tufClient, err := tuf.NewFromEnv(ctx)
	if err != nil {
		return nil, fmt.Errorf("initializing tuf: %w", err)
	}
	targetBytes, err := tufClient.GetTarget("trusted_root.json")
	if err != nil {
		return nil, fmt.Errorf("error getting targets: %w", err)
	}
	trustedRoot, err := root.NewTrustedRootFromJSON(targetBytes)
	if err != nil {
		return nil, fmt.Errorf("error creating trusted root: %w", err)
	}

	return trustedRoot, nil
}

func verifyBundles(bundles []*Bundle, desc *v1.Descriptor, trustedRoot *root.TrustedRoot, policy verify.PolicyBuilder, verifierOpts []verify.VerifierOption) ([]VerificationResult, error) {
	verifier, err := verify.NewSignedEntityVerifier(trustedRoot, verifierOpts...)
	if err != nil {
		return nil, err
	}

	verificationResults := make([]VerificationResult, 0)
	for _, bundle := range bundles {
		result, err := verifier.Verify(bundle.ProtoBundle, policy)
		if err == nil {
			verificationResults = append(verificationResults, VerificationResult{Bundle: bundle, Result: result, Desc: desc})
		} else {
			panic(err)
		}
	}

	return verificationResults, nil
}
