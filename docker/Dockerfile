FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

# Pinned exactly, deliberately: the CA bundle is the one input in this image that
# does not come from something already pinned (the base image is pinned by digest
# and the binaries are copied in), so leaving the package unpinned would let the
# trust store drift between identical builds.
#
# Alpine's main/ keeps only the latest build of a package, so this line fails
# loudly with "unable to select packages" once the version is superseded — which
# is what happened to 20260611-r0. Bump it then, rather than widening it to a
# range such as >=20260611, which would accept whatever Alpine published next.
RUN apk add --no-cache ca-certificates=20261020-r0

ARG TARGETARCH
COPY --chmod=755 ${TARGETARCH}/hbbs /usr/bin/hbbs
COPY --chmod=755 ${TARGETARCH}/hbbr /usr/bin/hbbr
COPY --chmod=755 ${TARGETARCH}/rustdesk-utils /usr/bin/rustdesk-utils
COPY --chmod=755 ${TARGETARCH}/starry-control-agent /usr/bin/starry-control-agent
COPY --chmod=755 ${TARGETARCH}/starry-relayctl /usr/bin/starry-relayctl
COPY --chmod=755 starry-relay-entrypoint.sh /usr/bin/starry-relay-entrypoint

ENV HOME=/root

WORKDIR /root
# Deliberately no VOLUME instruction: an omitted bind mount must not silently
# create an anonymous volume carrying identity or enrollment state.
EXPOSE 21115 21116 21116/udp 21117 21118 21119 21119/udp

CMD ["hbbs", "--starry-config=/root/starry/config.yaml"]
