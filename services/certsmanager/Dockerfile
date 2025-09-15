FROM alpine:3.22

RUN apk update && apk add --no-cache openssl

RUN mkdir /certs

COPY --chmod=0755 ./generate /certs/generate

COPY ./san_config.cnf /certs/san_config.cnf

WORKDIR /certs

ENTRYPOINT /certs/generate
