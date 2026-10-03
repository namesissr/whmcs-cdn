# Staging edge node: a plain Ubuntu 24.04 "server" that is provisioned at container start by the
# controller's real one-command installer (GET /edge/bootstrap.sh -> /edge/bundle.tar.gz ->
# edge/install.sh). See docs/STAGING.md for why this is an Ubuntu image and not a purpose-built one.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# The exact package set edge/install.sh installs for the distro nginx flavour, pre-installed (WITH
# recommends, like install.sh) so its apt-get install at runtime is a no-op transaction. install.sh
# still runs `apt-get update` itself, so the container needs outbound access to the Ubuntu mirrors.
# Second line: what install.sh expects on a real server (ip/tc, sysctl, modprobe) + an init (tini).
# Unpinned on purpose: the edge must get the same distro builds install.sh would pull today.
# hadolint ignore=DL3008,DL3015
RUN apt-get update -q \
 && apt-get install -y -q \
      nginx libnginx-mod-http-js libnginx-mod-http-geoip2 libnginx-mod-http-image-filter \
      libnginx-mod-http-brotli-filter libnginx-mod-stream \
      curl ca-certificates python3 python3-pil logrotate gzip \
 && apt-get install -y -q --no-install-recommends iproute2 procps kmod tini \
 && mkdir -p /etc/modules-load.d /etc/modprobe.d /etc/sysctl.d /etc/systemd/system \
 && rm -f /etc/nginx/sites-enabled/default \
 && rm -rf /var/lib/apt/lists/*

# systemd is not running in a container: a shim maps the systemctl calls install.sh and the agent
# make onto plain processes (nginx daemon, pcdn-imaged in the background; the agent itself runs in
# the foreground as the container's main process)
COPY systemctl /usr/local/bin/systemctl
COPY entrypoint.sh /usr/local/bin/staging-edge
RUN chmod 755 /usr/local/bin/systemctl /usr/local/bin/staging-edge

EXPOSE 80 443
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/staging-edge"]
