FROM python:3.11-slim
RUN pip install --no-cache-dir "paramiko>=3.4,<5" "httpx>=0.27,<1" && useradd -r -u 1001 attacker
WORKDIR /app
COPY attackers /app/attackers
USER 1001
ENTRYPOINT ["python", "-m", "attackers.crawler"]
