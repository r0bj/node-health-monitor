FROM artifactory.wikia-inc.com/dockerhub-remote/golang:1.23.3 AS builder

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o node-health-monitor .


FROM scratch

COPY --from=builder /workspace/node-health-monitor /

USER 65534:65534

ENTRYPOINT ["/node-health-monitor"]
