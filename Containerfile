# KeyClerk: one image, three commands (the reconciler, the read-only console and the desk), run as a non-root user.
# Build from a tag or a reviewed commit, never a working tree: git archive vX.Y.Z | podman build -t keyclerk:X.Y.Z -
# Reproducible (issue 49): the base pinned by digest, no bytecode, no dated files; built with the commit's time as
# SOURCE_DATE_EPOCH (podman build --timestamp, or buildx with rewrite-timestamp) a rebuild reaches the same digest.
# The daily rebuild passes BASE to move a released image onto a fixed base; the label says which base it is on.
ARG BASE=docker.io/library/python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54

FROM ${BASE} AS deps
ENV PYTHONDONTWRITEBYTECODE=1
COPY requirements.lock /tmp/
# A virtual environment without pip: the dependencies only, from hashes and wheels, nothing compiled here.
RUN python -m venv --without-pip /opt/venv \
    && pip --python /opt/venv/bin/python install --no-cache-dir --no-compile --require-hashes --only-binary=:all: \
       -r /tmp/requirements.lock

FROM ${BASE}
ARG BASE
LABEL org.opencontainers.image.source="https://github.com/keyclerk/keyclerk" \
      org.opencontainers.image.licenses="EUPL-1.2" \
      org.opencontainers.image.base.name="${BASE}"
WORKDIR /opt/keyclerk
# The emSign roots certifi dropped after the eMudhra key incident leave the trust store (tools/distrust_cas.sh).
COPY tools/distrust_cas.sh /tmp/
# The user is written, not added: useradd dates /etc/shadow, which would change the digest from day to day.
RUN sh /tmp/distrust_cas.sh && rm /tmp/distrust_cas.sh \
    && echo "keyclerk:x:10001:10001:KeyClerk:/nonexistent:/usr/sbin/nologin" >> /etc/passwd \
    && echo "keyclerk:x:10001:" >> /etc/group \
    && mkdir -p /var/lib/keyclerk && chown 10001:10001 /var/lib/keyclerk
COPY --from=deps /opt/venv /opt/venv
COPY LICENSE ./
# The engine itself is pure Python: copied, not installed, so no unpinned build tool enters the image.
COPY keyclerk ./keyclerk

USER 10001
ENV PYTHONUNBUFFERED=1 PYTHONPATH=/opt/keyclerk PYTHONDONTWRITEBYTECODE=1 PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin
ENTRYPOINT ["python", "-m"]
CMD ["keyclerk.reconcile", "--help"]
