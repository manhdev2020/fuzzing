FROM --platform=linux/amd64 python:3.12-alpine

USER root

WORKDIR /app

COPY . /app

RUN chmod +x /app/main.py

RUN apk -U upgrade \
    && apk add --no-cache \
        nmap \
        nmap-scripts \
    && rm -rf /var/cache/apk/*

RUN pip install -r requirements.txt

ENTRYPOINT ["/usr/local/bin/python", "/app/main.py"]