FROM python:3.11-slim
RUN pip install --no-cache-dir "fastapi>=0.110,<1" "uvicorn>=0.29,<1" && useradd -r -u 1001 wiki
WORKDIR /app
COPY honeynet/__init__.py /app/honeynet/__init__.py
COPY honeynet/wiki /app/honeynet/wiki
USER 1001
EXPOSE 80
CMD ["uvicorn", "honeynet.wiki.app:from_env", "--factory", "--host", "0.0.0.0", "--port", "80", "--no-server-header", "--no-access-log"]
