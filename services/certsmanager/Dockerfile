FROM alpine:3.8 as BASE

RUN apk update && apk add -y openssl

RUN mkdir /certs

COPY --chmod=0755 ./generate /certs/generate

COPY ./san_config.cnf /certs/san_config.cnf

WORKDIR /certs

ENTRYPOINT /certs/generate
