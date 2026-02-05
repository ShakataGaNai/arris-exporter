# Use a Python image with uv pre-installed
FROM ghcr.io/astral-sh/uv:python3.13-alpine

# Install the project into `/app`
WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Copy from the cache instead of linking since it's a mounted volume
ENV UV_LINK_MODE=copy

# Omit development dependencies
ENV UV_NO_DEV=1

# Install dependencies first for layer caching
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-install-project

# Then, add the rest of the project source code and install it
COPY arris_exporter.py .
RUN uv sync --locked

# Setup a non-root user
RUN adduser -D appuser

# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:$PATH"

# Reset the entrypoint, don't invoke `uv`
ENTRYPOINT []

# Use the non-root user to run our application
USER appuser

EXPOSE 9393

ENV UV_NO_CACHE=1
ENV MODEM_URL=https://192.168.100.1
ENV MODEM_USERNAME=admin
ENV EXPORTER_PORT=9393
ENV SCRAPE_INTERVAL=0

CMD ["uv", "run", "arris_exporter.py"]
