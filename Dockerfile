FROM golang:alpine@sha256:519c827ec22e5cf7417c9ff063ec840a446cdd30681700a16cf42eb43823e27c AS build
RUN apk update && apk add --no-cache git
WORKDIR /app
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o ./bin/server ./cmd/server

FROM alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300
RUN apk update && apk add --no-cache dumb-init
WORKDIR /app
COPY --from=build /app/bin/server ./server
COPY --from=build /app/jwks.json ./jwks.json
COPY --from=build /app/openid-configuration.json ./openid-configuration.json
COPY --from=build /app/private.pem ./private.pem
COPY --from=build /app/public.pem ./public.pem
CMD ["dumb-init", "/app/server"]
