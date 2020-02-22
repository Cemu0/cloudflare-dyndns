FROM golang:latest AS builder
ADD . /app/backend
WORKDIR /app/backend
RUN go mod download
RUN make

# Final Stage
FROM alpine:latest
#RUN apk --no-cache add ca-certificates
COPY --from=builder /app/main ./
RUN chmod +x ./main
ENTRYPOINT ["./main"]
#EXPOSE 3030