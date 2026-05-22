FROM python:3.11-slim
RUN pip install --no-cache-dir flask==3.0.0
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump && rm -rf /var/lib/apt/lists/*
COPY app.py /app/app.py
WORKDIR /app
RUN mkdir -p /app/captures
EXPOSE 5000
CMD ["python", "app.py"]
