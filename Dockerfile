FROM docker.io/golang:1.21.1
LABEL authors="Gustavo Luvizotto Cesar"

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /cert-validator

ENTRYPOINT ["/cert-validator"]

