FROM golang:1.22-alpine AS build
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN go build -o insta-assistant .

FROM alpine:3.20
WORKDIR /app
COPY --from=build /app/insta-assistant /usr/local/bin/insta-assistant
EXPOSE 8080
CMD ["insta-assistant"]
