# SafeSplit Go node
FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN go mod tidy
RUN CGO_ENABLED=0 go build -trimpath -o /safesplit-node .

FROM alpine:3.20
RUN adduser -D -u 1000 node
COPY --from=build /safesplit-node /usr/local/bin/safesplit-node
USER node
EXPOSE 8081
ENTRYPOINT ["safesplit-node"]
