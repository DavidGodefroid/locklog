# locklog in Docker: every locklog command runs in this image, through the
# launcher (scripts/locklog). The separated setup is baked in:
#
#   locklog (uid 10051)  the console account: it alone reads the logs and
#                        holds the keys, the policy and the audit (volume
#                        locklog-home)
#   agent   (uid 10052)  the agent side (locklog mcp), a member of
#                        locklog-clients (gid 10050): it reaches the
#                        console's socket (volume locklog-run)
#
# The kernel checks every peer on the socket as on a host.
#
#   docker build -t locklog .
#   docker build --target vault -t locklog:vault .   # with the vault CLI
#
# The base images are pinned by digest: update the tag and the digest
# together (docker buildx imagetools inspect alpine:3.22).

FROM golang:1.26-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# VERSION: the release version without its "v" (0.1.0), as goreleaser sets it.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/locklog ./cmd/locklog

# The HashiCorp Vault CLI, checked against the sums pinned here (update them
# with VAULT_VERSION from releases.hashicorp.com/vault/<version>/).
FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f AS vault-cli
ARG TARGETARCH
ARG VAULT_VERSION=2.2.0
ARG VAULT_SHA256_amd64=05d78b0ac842ca7c522fc297df91527cd43c15420c4c5c0a969d48a7b0ff7b6d
ARG VAULT_SHA256_arm64=9d9ae0ce520744fb095bdf150a6924f5583528fd385a2e92782f7a6d00cad53c
RUN set -eu; arch=${TARGETARCH:-amd64}; \
    case $arch in amd64) sum=$VAULT_SHA256_amd64 ;; arm64) sum=$VAULT_SHA256_arm64 ;; *) echo "no vault CLI for $arch" >&2; exit 1 ;; esac; \
    wget -qO /tmp/vault.zip "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_${arch}.zip"; \
    echo "$sum  /tmp/vault.zip" | sha256sum -c -; \
    unzip -q /tmp/vault.zip vault -d /out

FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f AS console
LABEL org.opencontainers.image.source="https://github.com/DavidGodefroid/locklog" \
      org.opencontainers.image.description="locklog: masked, bounded log search for AI agents, with a human-held console" \
      org.opencontainers.image.licenses="Apache-2.0"
# ALLOWED_UIDS: comma-separated uids that may reach the console besides the
# members of locklog-clients, for an agent in a container of its own whose
# uid has no account here. Root (0), the console account (10051), 65534
# (nobody) and leading zeros are refused. `locklog console --allowed-uids`
# does the same at run time, with the release image as it is.
ARG ALLOWED_UIDS=""
# ca-certificates: remote backends are checked with tls = "verify-full".
RUN case "$ALLOWED_UIDS" in *[!0-9,]*|,*|*,|*,,*) echo "ALLOWED_UIDS: comma-separated uids, got '$ALLOWED_UIDS'" >&2; exit 1;; esac \
 && for u in $(echo "$ALLOWED_UIDS" | tr ',' ' '); do \
      case "$u" in 0*|10051|65534) echo "ALLOWED_UIDS: $u is root, the console account, nobody (or has a leading zero)" >&2; exit 1;; esac; \
    done \
 && apk add --no-cache ca-certificates \
 && addgroup -S -g 10050 locklog-clients \
 && adduser -D -u 10051 -s /sbin/nologin -g "locklog console" locklog \
 && adduser -D -H -u 10052 -G locklog-clients -s /sbin/nologin -g "locklog agent" agent \
 && chmod 0700 /home/locklog \
 && install -d -m 0755 -o root -g root /etc/locklog \
 && printf '%s\n' \
      '# locklog: the console runs as service_user; members of client_group reach it.' \
      'service_user = "locklog"' \
      'client_group = "locklog-clients"' \
      'socket_dir   = "/run/locklog"' \
      'x11          = "refuse"' > /etc/locklog/system.toml \
 && if [ -n "$ALLOWED_UIDS" ]; then printf 'allowed_uids = [%s]\n' "$ALLOWED_UIDS" >> /etc/locklog/system.toml; fi \
 && chmod 0644 /etc/locklog/system.toml \
 && install -d -m 2750 -o locklog -g locklog-clients /run/locklog
COPY --from=build --chown=root:root --chmod=0755 /out/locklog /usr/local/bin/locklog

# Named volumes take these directories' owner and mode on first use; the
# launcher creates locklog-run from this image and checks its owner.
VOLUME ["/run/locklog", "/home/locklog"]
WORKDIR /
USER agent
ENTRYPOINT ["locklog"]
CMD ["help"]

# The console with the vault CLI, for credentials = "vault". Not the
# default: the CLI adds some 550 MB.
FROM console AS vault
COPY --from=vault-cli --chown=root:root --chmod=0755 /out/vault /usr/local/bin/vault

# The default image.
FROM console
