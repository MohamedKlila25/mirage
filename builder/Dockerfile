FROM python:3.11-slim
# pysigma: builder imports reliability/ (bedrock_call_llm), whose __init__ loads sigma_check
RUN pip install --no-cache-dir "pydantic>=2.5,<3" "pymongo>=4.6,<5" "boto3>=1.34" "pyyaml>=6" "pysigma>=2.0,<3" \
 && useradd -r -u 1001 builder
WORKDIR /app
COPY reliability /app/reliability
COPY canary /app/canary
COPY builder /app/builder
COPY honeynet/cowrie/base_fs.pickle /app/honeynet/cowrie/base_fs.pickle
USER 1001
ENTRYPOINT ["python", "-m", "builder.cli"]
