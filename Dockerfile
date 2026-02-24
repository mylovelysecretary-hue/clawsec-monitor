FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir cryptography

COPY clawsec-monitor.py /app/
COPY clawsec-api.py /app/

COPY setup-tailscale.sh /opt/clawsec/
COPY start-clawsec.sh /opt/clawsec/
RUN chmod +x /opt/clawsec/*.sh

EXPOSE 8080 8888

CMD ["sh", "/opt/clawsec/start-clawsec.sh"]
