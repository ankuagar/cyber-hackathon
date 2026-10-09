FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

USER root

EXPOSE 8080

ENTRYPOINT ["sh", "/app/entrypoint.sh"]
CMD ["python", "server.py"]
