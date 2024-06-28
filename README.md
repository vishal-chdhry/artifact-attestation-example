# Artifact attestation example

This repository contains a demo to verify Github's Artifact attestation using Kyverno.

Usage:
```bash
go run main.go --image ghcr.io/vishal-chdhry/artifact-attestation-example:artifact-attestation --predicate-type "https://slsa.dev/provenance/v1" --subject "https://github.com/vishal-chdhry/artifact-attestation-example/.github/workflows/build-attested-image.yaml@refs/heads/main"
```
