FROM python:3.11-slim
RUN pip install --no-cache-dir flask==3.0.0 requests==2.31.0
COPY app.py /app/app.py
WORKDIR /app
EXPOSE 5000
CMD ["python", "app.py"]
