FROM python:3.13-slim@sha256:8d9d0b8bcf6506481eae4907c18f5e3e7902e629f5f6d684f9e7c32e85e3ddf0 AS build
WORKDIR /build
COPY pyproject.toml requirements.lock README.md ./
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock
COPY src ./src
RUN python -m build --wheel --no-isolation

FROM python:3.13-slim@sha256:8d9d0b8bcf6506481eae4907c18f5e3e7902e629f5f6d684f9e7c32e85e3ddf0
COPY --from=build /build/dist/*.whl /tmp/wheels/
COPY requirements-runtime.lock /tmp/requirements-runtime.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/requirements-runtime.lock && python -m pip install --no-cache-dir --no-deps /tmp/wheels/*.whl
COPY deploy/service_entrypoint.py /app/service_entrypoint.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 11007:11007
ENTRYPOINT ["python", "-I", "/app/service_entrypoint.py"]
