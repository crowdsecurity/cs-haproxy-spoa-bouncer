ARG GOVERSION=1.25

FROM golang:${GOVERSION}-alpine AS build

WORKDIR /go/src/cs-spoa-bouncer

RUN apk add --update --no-cache make git ca-certificates
COPY . .

RUN make build DOCKER_BUILD=1

# Final minimal image
FROM scratch

# Copy CA certificates for HTTPS connections to LAPI
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the static binary
COPY --from=build /go/src/cs-spoa-bouncer/crowdsec-spoa-bouncer /crowdsec-spoa-bouncer

# Copy default config file
COPY --from=build /go/src/cs-spoa-bouncer/config/crowdsec-spoa-bouncer.yaml /etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml

# Copy Lua files for HAProxy integration
COPY --from=build /go/src/cs-spoa-bouncer/lua/ /usr/lib/crowdsec-haproxy-spoa-bouncer/lua/

# Copy HTML templates for ban/captcha pages
COPY --from=build /go/src/cs-spoa-bouncer/templates/ /var/lib/crowdsec-haproxy-spoa-bouncer/html/

EXPOSE 9000

ENTRYPOINT ["/crowdsec-spoa-bouncer"]
CMD ["-c", "/etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml"]
