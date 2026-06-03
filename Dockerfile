FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY src/ /app/

RUN useradd -m -u 10001 honeypot \
    && mkdir -p /data /opt/decoy \
    && chown -R honeypot:honeypot /data /opt/decoy /app \
    && printf "db_password=supersecret\napi_key=AKIAEXAMPLE\n" > /opt/decoy/credentials.txt \
    && printf "Project Plan\nConfidential\n" > /opt/decoy/roadmap.txt \
    && printf "Sample archive placeholder\n" > /opt/decoy/secrets.zip

USER honeypot

EXPOSE 2222

CMD ["python", "/app/honeypot.py"]
