# Use the official Golang Alpine image as the base image
FROM golang:alpine

# Set the working directory inside the container
WORKDIR /app

# Install libvips and its dependencies
RUN apk --no-cache add build-base \
    && apk --no-cache add vips-dev \
    && apk --no-cache add gcc \
    && apk --no-cache add g++ \
    && apk --no-cache add libc6-compat

# Copy the go.mod and go.sum files to download dependencies
# This is done before copying the source code to leverage Docker cache
COPY go.mod go.sum ./

# Download the dependencies
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the application
RUN go build -o main .

# Command to run the executable
CMD ["./main"]
