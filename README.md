# Image Processing Service

This service provides an API for image processing, converting images to the WebP format, and caching them for efficient retrieval.

## Development

### Prerequisites

- Go 1.18 or higher
- Docker and Docker Compose (for containerization and local testing)
- An understanding of Go modules and HTTP server handling

### Setting Up Your Development Environment

1. **Clone the Repository:**

   ```bash
   git clone [repository URL]
   cd my-image-service
   ```

2. **Install Dependencies:**

   The project uses Go modules for dependency management.

   ```bash
   go mod tidy
   ```

3. **Environment Variables:**

   Set the necessary environment variables (e.g., `API_SECRET`). You can do this by exporting them in your shell or by setting them in a `.env` file at the root of the project.

4. **Running the Application Locally:**

   To run the service locally:

   ```bash
   go run ./cmd/server/main.go
   ```

   This will start the server on `localhost:8080` (or another port, if configured).

## Building the Application

1. **Building a Binary:**

   Compile the application into a binary:

   ```bash
   go build -o image-service ./cmd/server
   ```

2. **Building a Docker Image:**

   Use the provided `Dockerfile` to build a Docker image:

   ```bash
   docker build -t image-service .
   ```

3. **Using Docker Compose:**

   Alternatively, use Docker Compose to build and run the service:

   ```bash
   docker-compose up --build
   ```

## Usage

After starting the service, you can interact with it via HTTP requests:

1. **Convert an Image to WebP:**

   Send a request to the service with the image URL:

   ```bash
   curl http://localhost:8080/path/to/image
   ```

   The server will return the WebP converted image.

2. **Health Check:**

   To check the health of the service:

   ```bash
   curl http://localhost:8080/health
   ```

## Additional Information

- **Configuration:** See `configs/config.yaml` for configuration options.
- **Logging:** The service uses `logrus` for logging. Logs are output in JSON format.
- **Caching:** Cached images are stored temporarily as defined in the configuration.

## Contributing

Contributions to this project are welcome. Please adhere to the project's coding standards and submit pull requests for any new features or bug fixes.

## License

[Specify the license here]

---

For more information, please refer to the in-depth documentation in the `/docs` directory.
