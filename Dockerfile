# Use the official Golang image as the base image
FROM golang:latest

ENV http_proxy http://10.0.11.92:1090
ENV https_proxy http://10.0.11.92:1090

RUN apt-get update && \
    apt-get install -y libvips-dev

# Set the working directory inside the container
WORKDIR /app

# Copy the Go source code and other necessary files to the container
COPY . .

# Build the Go application
RUN go build -o main .

# Expose the port that your application listens on
EXPOSE 8080

# Define the command to run your application
ENV http_proxy ""
ENV https_proxy ""
CMD ["./main"]
