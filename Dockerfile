FROM golang:1.22-alpine AS builder
WORKDIR $GOPATH/src/github.com/github.com/trivy-web-dash
COPY . .
RUN go build -ldflags '-extldflags "-static"' -o trivy-web-dashboard

FROM ubuntu:latest AS final
RUN apt update && apt install -y curl && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin latest
WORKDIR /opt/
COPY --from=builder go/src/github.com/github.com/trivy-web-dash/trivy-web-dashboard .
COPY templates templates
EXPOSE 8001
CMD ["./trivy-web-dashboard"]