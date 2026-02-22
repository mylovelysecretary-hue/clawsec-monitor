FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir cryptography

COPY clawsec-monitor.py /app/
COPY clawsec-api.py /app/

EXPOSE 8080

CMD ["python3", "-c", "
import sys
with open('clawsec-api.py') as f:
    code = f.read().replace('port=8889', 'port=8080')
exec(code)
"]
