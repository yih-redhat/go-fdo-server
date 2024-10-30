# Variables
IMAGE_NAME = fdo_server
CONTAINER_NAME = fdo_server
DB_PATH = ./test.db
DB_PASS =
NETWORK = host
DEBUG = --debug
HTTP_ADDR = localhost:8080
EXT_HTTP_ADDR = 127.0.0.1:8080
UPLOAD_DIR = /app-data/
DOWNLOAD_FILES =
UPLOAD_FILES =
IMPORT_VOUCHER =
INSECURE_TLS =
PRINT_OWNER_PUBLIC =
RESALE_GUID =
RESALE_KEY =
REUSE_CRED =
WGET_URLS =

# Build the Docker image
build:
	docker build -t $(IMAGE_NAME) .

# Run the Docker container with all flags
run:
	docker run -v $(PWD)/app-data:/app-data:rw --name $(CONTAINER_NAME) -d --network=$(NETWORK) $(IMAGE_NAME) \
		-db $(DB_PATH) \
		$(if $(DB_PASS),-db-pass $(DB_PASS)) \
		$(DEBUG) \
		-http $(HTTP_ADDR) \
		-ext-http $(EXT_HTTP_ADDR) \
		-upload-dir $(UPLOAD_DIR) \
		$(foreach file,/app-data/$(DOWNLOAD_FILES),-download $(file)) \
		$(foreach file,$(UPLOAD_FILES),-upload $(file)) \
		$(if $(IMPORT_VOUCHER),-import-voucher $(IMPORT_VOUCHER)) \
		$(if $(INSECURE_TLS),-insecure-tls) \
		$(if $(PRINT_OWNER_PUBLIC),-print-owner-public $(PRINT_OWNER_PUBLIC)) \
		$(if $(RESALE_GUID),-resale-guid $(RESALE_GUID)) \
		$(if $(RESALE_KEY),-resale-key $(RESALE_KEY)) \
		$(if $(REUSE_CRED),-reuse-cred) \
		$(foreach url,$(WGET_URLS),-wget $(url))

# Docker stop
stop:
	docker stop $(CONTAINER_NAME)
	docker rm $(CONTAINER_NAME)

# Clean up Docker images
clean:
	docker rmi $(IMAGE_NAME)

# Default target
all: build run
