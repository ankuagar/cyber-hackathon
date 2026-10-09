FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/archive
RUN chmod 777 /app/archive

USER 65534

CMD ["python", "archive.py"]
