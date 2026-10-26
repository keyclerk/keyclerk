# KeyClerk: one image, three commands (the reconciler, the read-only console and the desk), run as a non-root user.
# Build from a tag or a reviewed commit, never a working tree: git archive vX.Y.Z | podman build -t keyclerk:X.Y.Z -
FROM docker.io/library/python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f

WORKDIR /opt/keyclerk
COPY LICENSE requirements.lock ./
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements.lock && useradd --system --uid 10001 --no-create-home keyclerk \
    && mkdir -p /var/lib/keyclerk && chown keyclerk /var/lib/keyclerk

# The engine itself is pure Python: copied, not installed, so no unpinned build tool enters the image.
COPY keyclerk ./keyclerk

USER 10001
ENV PYTHONUNBUFFERED=1 PYTHONPATH=/opt/keyclerk PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python", "-m"]
CMD ["keyclerk.reconcile", "--help"]
