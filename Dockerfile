FROM python:3.12.7-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY aegis ./aegis
COPY web ./web
COPY fixtures ./fixtures
COPY sentinel ./sentinel

RUN useradd --uid 10001 --create-home aegis \
    && mkdir -p /app/var/workspace \
    && chown -R aegis:aegis /app

USER aegis

ENV AEGIS_HOST=0.0.0.0
ENV AEGIS_LISTEN_PORT=8787

EXPOSE 8787

CMD ["python", "-m", "aegis"]
