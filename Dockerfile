FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# HTTP (no certs). Mount certs at /app/key.pem + /app/cert.pem for TLS 1.3 / port 8443.
EXPOSE 8080 8443

ENV PYTHONUNBUFFERED=1

CMD ["python", "server.py"]
