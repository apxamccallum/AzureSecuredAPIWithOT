FROM golang:1.17-alpine

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . ./

RUN ls -al

RUN go build -o /myapi

EXPOSE 3000

CMD [ "/myapi" ]