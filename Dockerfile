FROM python:3.12-slim

WORKDIR /app

# Install curl, tar and ca-certificates for Tailscale
RUN apt-get update && apt-get install -y curl tar ca-certificates && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir cryptography

COPY clawsec-monitor.py /app/
COPY clawsec-api.py /app/

COPY opt/clawsec/setup-tailscale.sh /opt/clawsec/
COPY opt/clawsec/start-clawsec.sh /opt/clawsec/
RUN chmod +x /opt/clawsec/*.sh

EXPOSE 8080 8888

CMD ["sh", "/opt/clawsec/start-clawsec.sh"]
