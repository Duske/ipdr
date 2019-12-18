FROM golang:alpine AS builder
RUN mkdir /app
ADD . /app/
WORKDIR /app
RUN go build -o ipdr cmd/ipdr/main.go

FROM alpine
RUN mkdir /app
WORKDIR /app
COPY --from=builder /app/ipdr .

EXPOSE 5000
ENTRYPOINT ["./ipdr"]
CMD ["server"]