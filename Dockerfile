FROM python:3.11-slim

WORKDIR /app

COPY controller/ .

RUN pip install --no-cache-dir -r requirements.txt

CMD ["kopf", "run", "--all-namespaces", "main.py"]