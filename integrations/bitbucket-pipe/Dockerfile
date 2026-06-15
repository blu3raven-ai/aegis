FROM alpine:3.20

RUN apk add --no-cache bash curl jq ca-certificates

COPY scripts/trigger.sh /usr/local/bin/trigger.sh
RUN chmod +x /usr/local/bin/trigger.sh

ENTRYPOINT ["/usr/local/bin/trigger.sh"]
