FROM python:3.11-slim
RUN pip install --no-cache-dir "fastapi>=0.110,<1" "uvicorn>=0.29,<1" "boto3>=1.34" && useradd -r -u 1001 gateway
WORKDIR /app
COPY honeynet/__init__.py /app/honeynet/__init__.py
COPY honeynet/gateway /app/honeynet/gateway
USER 1001
EXPOSE 8080
CMD ["uvicorn", "honeynet.gateway.app:from_env", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
