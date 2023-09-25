FROM docker.io/golang:1.21.1
LABEL authors="Gustavo Luvizotto Cesar"

RUN apt-get update -y
RUN apt-get install curl -y

RUN git clone https://github.com/gustavoluvizotto/cert-validator.git
RUN cd cert-validator && go install .

ENTRYPOINT ["/go/bin/cert-validator"]

