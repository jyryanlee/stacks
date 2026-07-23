ARG FLARESOLVERR_IMAGE=ghcr.io/flaresolverr/flaresolverr:v3.5.0@sha256:139dfee1c6f89249c8d665d1333a42e8ec74ec0a86bc6bb1c8461e10d3a66a47
FROM ${FLARESOLVERR_IMAGE}

USER root

COPY patch_flaresolverr.py /opt/stacks-flaresolverr/patch_flaresolverr.py

# Patch only the two pinned upstream source files. The patcher checks exact
# v3.5.0 anchors and aborts instead of silently applying to a different tree.
RUN python /opt/stacks-flaresolverr/patch_flaresolverr.py apply /app \
    && python /opt/stacks-flaresolverr/patch_flaresolverr.py verify /app \
    && python -m py_compile /app/flaresolverr_service.py /app/utils.py

USER flaresolverr
