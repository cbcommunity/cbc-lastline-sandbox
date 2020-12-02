FROM python:3.8
MAINTAINER Ryan Fortress (rfortress@vmware.com)

WORKDIR /code
RUN cd /code && mkdir /app

COPY requirements.txt .

ADD entrypoint.sh .
RUN chmod +x ./entrypoint.sh

ENTRYPOINT ./entrypoint.sh