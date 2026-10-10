# Minimal hardened sandbox image for Gatekeeper kernel isolation & syscall tracing
# Build: docker build -t gatekeeper-sandbox:latest -f sandbox/Dockerfile sandbox/
# Usage: GATEKEEPER_SANDBOX_IMAGE=gatekeeper-sandbox:latest (or pass image="gatekeeper-sandbox:latest")
FROM alpine:3.20

# Install minimal lifecycle runtimes and strace for syscall capture
RUN apk update && \
    apk add --no-cache \
        bash \
        strace \
        python3 \
        py3-pip \
        nodejs \
        npm \
        coreutils \
        ca-certificates && \
    rm -rf /var/cache/apk/*

# Create unprivileged sandbox user (UID/GID 1000)
RUN addgroup -g 1000 sandbox && \
    adduser -D -u 1000 -G sandbox -s /bin/sh sandbox

# Prepare workspace and trace mount directories
RUN mkdir -p /workspace /workspace/output /sysdrift_trace /sysdrift_runner && \
    chown -R sandbox:sandbox /workspace /sysdrift_trace /sysdrift_runner

# Working directory
WORKDIR /workspace

# Default user
USER sandbox

CMD ["/bin/sh"]
