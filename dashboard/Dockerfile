FROM python:3.11-slim
RUN pip install --no-cache-dir "streamlit>=1.50,<2" "pymongo>=4.6,<5" \
 && useradd -r -m -u 1001 dashboard
WORKDIR /app
COPY dashboard /app/dashboard
ENV PYTHONPATH=/app
USER 1001
EXPOSE 8501
CMD ["streamlit", "run", "dashboard/app.py", "--server.address=0.0.0.0", "--server.port=8501", \
     "--server.headless=true", "--browser.gatherUsageStats=false"]
