# VMP engine image. Red Hat UBI 9 base: FIPS-capable when the host runs in FIPS mode,
# suitable for a FedRAMP Moderate GovCloud deployment.
# TODO before deployment: pin both FROM lines and the uv image by digest (@sha256:...).

FROM registry.access.redhat.com/ubi9/python-312 AS build
USER 0
COPY --from=ghcr.io/astral-sh/uv:0.12.24 /uv /usr/local/bin/uv
WORKDIR /app
# Use the image's Python (never download one) and install only what uv.lock pins.
ENV UV_PYTHON_DOWNLOADS=never UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM registry.access.redhat.com/ubi9/python-312
COPY --from=build --chown=1001:0 /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"
WORKDIR /app
USER 1001
CMD ["python", "-c", "import vmp; print('vmp', vmp.__version__)"]
