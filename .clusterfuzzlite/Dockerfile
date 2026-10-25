# SPDX-License-Identifier: EUPL-1.2
# The ClusterFuzzLite build image for tools/fuzz_*.py: OSS-Fuzz's Python builder (Atheris included), pinned by digest,
# with the verifier's one dependency installed hash-locked.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:21f6fab17ace4dc76e1c56de91ee95d3d03da021df94b41056ba036f6c6f55e9
COPY .clusterfuzzlite/requirements-fuzz.txt /tmp/requirements-fuzz.txt
RUN pip3 install --require-hashes --only-binary=:all: -r /tmp/requirements-fuzz.txt
COPY . $SRC/keyclerk
WORKDIR $SRC/keyclerk
COPY .clusterfuzzlite/build.sh $SRC/
