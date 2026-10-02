FROM python:3.12-slim

# pg_dump / pg_restore must be at least the server's major version (docker-compose runs postgres:16)
ARG PG_MAJOR=16

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl openssl ca-certificates gnupg \
 && install -d /usr/share/postgresql-common/pgdg \
 && curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc \
 && . /etc/os-release \
 && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" \
      > /etc/apt/sources.list.d/pgdg.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends postgresql-client-${PG_MAJOR} \
 && apt-get purge -y gnupg && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL https://github.com/acmesh-official/acme.sh/archive/refs/heads/master.tar.gz | tar xz -C /tmp \
 && cd /tmp/acme.sh-master && ./acme.sh --install --nocron --home /root/.acme.sh \
 && rm -rf /tmp/acme.sh-master

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY alembic.ini ./
COPY migrations ./migrations
COPY app ./app
COPY acme/dns_pcdn.sh /root/.acme.sh/dnsapi/dns_pcdn.sh

ENV DATABASE_URL=sqlite:////data/cdn.db ACME_HOME=/data/acme BACKUP_DIR=/data/backups
# L3 (security review): proxy headers (client IP, scheme) are trusted only from these addresses —
# the reverse proxy (Caddy) on a private Docker network / private link. Override with
# FORWARDED_ALLOW_IPS (comma separated IPs / networks, read by uvicorn); never "*".
ENV FORWARDED_ALLOW_IPS=127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
VOLUME ["/data"]
EXPOSE 8000
# the schema is created / upgraded at startup (Alembic); see docs/OPERATIONS.md
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
