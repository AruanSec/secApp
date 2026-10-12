FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/lib \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY app ./app

ARG APP_UID=10001
ARG APP_GID=10001
RUN groupadd --gid "$APP_GID" app \
    && useradd --no-log-init --uid "$APP_UID" --gid app --no-create-home app \
    && mkdir -p /app/data \
    && chown app:app /app/data

USER app

EXPOSE 8000

CMD ["/app/lib/bin/uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
