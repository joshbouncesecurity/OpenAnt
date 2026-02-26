FROM golang:1.22-alpine
WORKDIR /test
COPY go.mod .
RUN go mod download
COPY test_exploit.go .
RUN go build -o test_exploit test_exploit.go
CMD ["./test_exploit"]
