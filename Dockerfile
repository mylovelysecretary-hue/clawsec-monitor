FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir cryptography

COPY clawsec-monitor.py /app/
COPY clawsec-api.py /app/

EXPOSE 8888 8889

CMD ["python3", "clawsec-api.py", "start"]
