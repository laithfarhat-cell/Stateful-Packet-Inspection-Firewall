FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libnetfilter-queue-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir . 'NetfilterQueue>=1.1'
ENTRYPOINT ["python", "main.py"]
CMD ["--mode", "replay"]
