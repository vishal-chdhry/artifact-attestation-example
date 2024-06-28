FROM golang:alpine3.18

WORKDIR /
COPY . ./

RUN go build -o main .

ENTRYPOINT ["/main"]
