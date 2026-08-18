FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home --home-dir /app --shell /usr/sbin/nologin app

# Owned by the unprivileged runtime user so that Docker copies this ownership onto a freshly
# created bootstrap-secret volume. Without it the volume is root-owned and secret generation
# would need a separate privileged container.
RUN mkdir -p /run/leakcheck-bootstrap \
    && chown app:app /run/leakcheck-bootstrap \
    && chmod 0755 /run/leakcheck-bootstrap

WORKDIR /app

COPY requirements.txt ./
RUN pip install --require-hashes --no-compile -r requirements.txt

COPY --chown=app:app app ./app
COPY --chown=app:app alembic.ini ./
COPY --chown=app:app migrations ./migrations

USER app:app
EXPOSE 8000

CMD ["uvicorn", "--factory", "app.main:create_app", "--host", "0.0.0.0", "--port", "8000"]
