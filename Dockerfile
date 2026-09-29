FROM python:3.12-slim

RUN useradd -u 1000 -m collector
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY egypt_asn_collector.py .

USER collector

# Fleet/CronJob passes --out; this default is only for `docker run` testing.
ENTRYPOINT ["python3", "egypt_asn_collector.py"]
CMD ["--out", "/output"]
