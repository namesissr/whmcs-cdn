FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL https://github.com/acmesh-official/acme.sh/archive/refs/heads/master.tar.gz | tar xz -C /tmp \
 && cd /tmp/acme.sh-master && ./acme.sh --install --nocron --home /root/.acme.sh \
 && rm -rf /tmp/acme.sh-master

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY acme/dns_pcdn.sh /root/.acme.sh/dnsapi/dns_pcdn.sh

ENV DATABASE_URL=sqlite:////data/cdn.db ACME_HOME=/data/acme
VOLUME ["/data"]
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
