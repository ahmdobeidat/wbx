# wbx: bundled offline scanner (semgrep + codeql + rules)
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl unzip git ca-certificates && rm -rf /var/lib/apt/lists/*

# CodeQL CLI (pin a known-good release)
ARG CODEQL_VERSION=2.24.2
RUN curl -sSL -o /tmp/codeql.zip \
      https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip \
    && unzip -q /tmp/codeql.zip -d /opt && rm /tmp/codeql.zip
ENV PATH="/opt/codeql:${PATH}"

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -e . && pip install --no-cache-dir semgrep

# Prefetch CodeQL query packs into the image (needs network AT BUILD time only)
RUN codeql pack download codeql/python-queries codeql/javascript-queries \
      codeql/ruby-queries codeql/java-queries || true

ENTRYPOINT ["wbx"]
CMD ["--help"]
