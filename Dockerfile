ARG GOVERSION=1.22.2

FROM golang:${GOVERSION}-alpine AS build

WORKDIR /go/src/cs-spoa-bouncer

RUN apk add --update --no-cache make git
COPY . .

RUN make build

FROM alpine:latest
COPY --from=build /go/src/cs-spoa-bouncer/crowdsec-spoa-bouncer /usr/local/bin/crowdsec-spoa-bouncer
COPY --from=build /go/src/cs-spoa-bouncer/config/crowdsec-spoa-bouncer.yaml /etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml
COPY --from=build /go/src/cs-spoa-bouncer/docker/docker_start.sh /docker_start.sh

## Add the same haproxy user as the official haproxy image
RUN addgroup -g 99 -S haproxy && adduser -S -D -H -u 99 -h /var/lib/haproxy -s /sbin/nologin -G haproxy -g haproxy haproxy
## Add worker user
RUN addgroup -S crowdsec-spoa && adduser -S -D -H -s /usr/sbin/nologin -g crowdsec-spoa crowdsec-spoa

## Create a socket for the spoa to inherit crowdsec-spoa:haproxy user from official haproxy image
RUN mkdir -p /run/crowdsec-spoa/ && chown crowdsec-spoa:haproxy /run/crowdsec-spoa/ && chmod 770 /run/crowdsec-spoa/
RUN touch /run/crowdsec-spoa/spoa-1.sock && chown crowdsec-spoa:haproxy /run/crowdsec-spoa/spoa-1.sock && chmod 660 /run/crowdsec-spoa/spoa-1.sock

## Copy templates
RUN mkdir -p /var/lib/crowdsec/lua/haproxy/templates/
COPY --from=build /go/src/cs-spoa-bouncer/templates/* /var/lib/crowdsec/lua/haproxy/templates/

RUN mkdir -p /usr/local/crowdsec/lua/haproxy/
COPY --from=build /go/src/cs-spoa-bouncer/lua/* /usr/local/crowdsec/lua/haproxy/

RUN chown -R root:haproxy /var/lib/crowdsec/lua/haproxy /usr/local/crowdsec/lua/haproxy

VOLUME [ "/usr/local/crowdsec/lua/haproxy/", "/var/lib/crowdsec/lua/haproxy/templates/" ]

RUN chmod +x /docker_start.sh

ENTRYPOINT ["/docker_start.sh"]
