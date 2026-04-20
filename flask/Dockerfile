FROM python:3.11-slim

WORKDIR /opt/memento/flask

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN pip install --upgrade pip --no-cache-dir
COPY ./requirements.txt .
RUN pip install -r requirements.txt --no-cache-dir

COPY *.py ./