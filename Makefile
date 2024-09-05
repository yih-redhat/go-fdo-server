# Variables
IMAGE_NAME = fdo_server
CONTAINER_NAME = fdo_server
DB_PATH = ./test.db
DB_PASS =
NETWORK = host
DEBUG = --debug
HTTP_ADDR = localhost:8080
EXT_HTTP_ADDR = 127.0.0.1:8080
RV_BYPASS =
TO0_ADDR =
TO0_GUID =
UPLOAD_DIR = uploads
DOWNLOAD_FILES =
UPLOAD_FILES =

# Build the Docker image
build:
	docker build -t $(IMAGE_NAME) .

# Run the Docker container with all flags
run:
	docker run --name $(CONTAINER_NAME) -d --network=$(NETWORK) $(IMAGE_NAME) \
		-db $(DB_PATH) \
		$(if $(DB_PASS),-db-pass $(DB_PASS)) \
		$(DEBUG) \
		-http $(HTTP_ADDR) \
		-ext-http $(EXT_HTTP_ADDR) \
		$(if $(RV_BYPASS),-rv-bypass) \
		$(if $(TO0_ADDR),-to0 $(TO0_ADDR)) \
		$(if $(TO0_GUID),-to0-guid $(TO0_GUID)) \
		-upload-dir $(UPLOAD_DIR) \
		$(foreach file,$(DOWNLOAD_FILES),-download $(file)) \
		$(foreach file,$(UPLOAD_FILES),-upload $(file))

# Docker stop
stop:
	docker stop $(CONTAINER_NAME)
	docker rm $(CONTAINER_NAME)

# Clean up Docker images
clean:
	docker rmi $(IMAGE_NAME)

# Default target
all: build run