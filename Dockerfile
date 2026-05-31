FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV SS_HOST=0.0.0.0 \
    SS_PORT=5000 \
    SS_DEBUG=0

EXPOSE 5000

# Generate a self-signed cert on first boot if one isn't mounted in, then run.
CMD ["sh", "-c", "[ -f server.crt ] || python generate_certificates.py; python simple_secure_server.py"]
