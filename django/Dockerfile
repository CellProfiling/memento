FROM python:3.8.3-slim

WORKDIR /opt/memento/django

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

#RUN apt-get update
#RUN apt-get install -y build-essential

RUN pip install --upgrade pip
COPY ./requirements.txt .
RUN pip install -r requirements.txt

COPY mementosite .
