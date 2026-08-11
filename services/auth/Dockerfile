FROM golang:1.23-alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -o /out/auth-server ./cmd/server

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=build /out/auth-server /app/auth-server
COPY migrations /app/migrations
ENV KEEPPAM_MIGRATIONS_DIR=/app/migrations
EXPOSE 8080
USER nobody
ENTRYPOINT ["/app/auth-server"]
