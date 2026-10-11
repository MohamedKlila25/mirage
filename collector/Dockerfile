FROM python:3.11-slim
RUN pip install --no-cache-dir "pymongo>=4.6,<5" && useradd -r -u 1001 collector && mkdir /state && chown 1001 /state
WORKDIR /app
COPY collector /app/collector
COPY canary /app/canary
USER 1001
CMD ["python", "-m", "collector.collector"]
