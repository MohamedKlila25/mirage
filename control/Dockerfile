FROM python:3.11-slim
# pysigma + pyyaml: control imports reliability/, whose __init__ loads sigma_check (it crashed without them)
RUN pip install --no-cache-dir "mcp>=2.2,<3" "pydantic>=2.5,<3" "pymongo>=4.6,<5" "pysigma>=2.0,<3" "pyyaml>=6" \
 && useradd -r -u 1001 control \
 && mkdir -p /deception /control /exports /audit && chown 1001 /deception /control /exports /audit
WORKDIR /app
COPY reliability /app/reliability
COPY brain /app/brain
COPY builder /app/builder
COPY canary /app/canary
COPY honeynet/cowrie/base_fs.pickle /app/honeynet/cowrie/base_fs.pickle
COPY control /app/control
USER 1001
EXPOSE 8100
CMD ["python", "-m", "control.server"]
