FROM python:3.11-slim
RUN pip install --no-cache-dir flask==3.0.0
RUN echo "FLAG{path_traversal_to_victory}" > /flag.txt
COPY app.py /app/app.py
WORKDIR /app
EXPOSE 5000
CMD ["python", "app.py"]
