FROM golang:1.22-alpine AS builder
WORKDIR $GOPATH/src/github.com/github.com/trivy-web-dash
COPY . .
RUN go build -ldflags '-extldflags "-static"' -o trivy-web-dashboard

FROM scratch
WORKDIR /opt/
COPY --from=builder go/src/github.com/github.com/trivy-web-dash/trivy-web-dashboard .
COPY templates templates
EXPOSE 8001
CMD ["./trivy-web-dashboard"]