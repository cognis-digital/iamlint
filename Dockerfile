FROM python:3.12-slim
LABEL org.opencontainers.image.title="cognis-iamlint"
LABEL org.opencontainers.image.source="https://github.com/cognis-digital/iamlint"
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .
ENTRYPOINT ["iamlint"]
