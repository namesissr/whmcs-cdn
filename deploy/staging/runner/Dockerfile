# Staging test runner: provisions the edges through the admin API, then hosts the pytest run.
FROM python:3.12-slim

# hadolint ignore=DL3008
RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends dnsutils curl \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir "pytest>=8,<9" "boto3>=1.34,<2"

COPY provision.py /opt/staging/provision.py
WORKDIR /tests
CMD ["python", "/opt/staging/provision.py", "--then-sleep"]
