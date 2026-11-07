- The image workflow names the Containerfile (BuildKit looks for a Dockerfile by default, so 0.29.0-rc.1's image jobs
  found nothing to build), and a maintainer can build a tag's images again by hand. The engine image moves to the
  current Python 3.12 slim base (Python 3.12.16): the scan found a fixable critical finding in the earlier one.
- The pushed image is the digest the two builds reproduced: BuildKit's own attestations are off (GitHub's attest the
  digest instead) and the push uses OCI media types, as the comparison builds do.
