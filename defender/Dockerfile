FROM python:3.11-slim
RUN pip install --no-cache-dir "pydantic>=2.5,<3" "pysigma>=2.0,<3" "pyyaml>=6" "pymongo>=4.6,<5" "boto3>=1.34" \
 && useradd -r -u 1001 defender && mkdir /audit && chown 1001 /audit
WORKDIR /app
COPY reliability /app/reliability
COPY defender /app/defender
USER 1001
CMD ["python", "-m", "defender.service"]
