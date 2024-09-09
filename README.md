# FIDO Device Onboard - Go Server

`go-fdo-server` is a server implementation of FIDO Device Onboard specification in Go.

[fdo]: https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v1.1-20220419/FIDO-Device-Onboard-PS-v1.1-20220419.html
[cbor]: https://www.rfc-editor.org/rfc/rfc8949.html
[cose]: https://datatracker.ietf.org/doc/html/rfc8152

## Building the Example Server Application

The example server application can be built with `go build` directly

```console
$ go build -o fdo_server ./cmd/fdo_server/
$ ./fdo_server

Usage:
  fdo_server [--] [options]

Server options:
  -db string
        SQLite database file path
  -db-pass string
        SQLite database encryption-at-rest passphrase
  -debug
        Print HTTP contents
  -download file
        Use fdo.download FSIM for each file (flag may be used multiple times)
  -ext-http addr
        External address devices should connect to (default "127.0.0.1:${LISTEN_PORT}")
  -http addr
        The address to listen on (default "localhost:8080")
  -rv-bypass
        Skip TO1
  -to0 addr
        Rendezvous server address to register RV blobs (disables self-registration)
  -to0-guid guid
        Device guid to immediately register an RV blob (requires to0 flag)
  -upload file
        Use fdo.upload FSIM for each file (flag may be used multiple times)
  -upload-dir path
        The directory path to put file uploads (default "uploads")
```

## Building and Running the Example Server Application using Containers

### Prerequisites

- Docker
- Make

### Makefile Targets

- `build`: Builds the Server image.
- `run`: Runs the Server container.
- `clean`: Removes the Server image.
- `all`: Builds the Server image and then runs the container.

### Variables

The following variables can be set to customize the behavior of the `make run` command:

- `IMAGE_NAME`: The name of the Docker image (default: `fdo_server`).
- `DB_PATH`: The path to the SQLite database file (default: `./test.db`).
- `DB_PASS`: The SQLite database encryption-at-rest passphrase.
- `NETWORK`: The Docker network setting (default: `host`).
- `DEBUG`: Debug flag to print HTTP contents (default: `--debug`).
- `HTTP_ADDR`: The address to listen on (default: `localhost:8080`).
- `EXT_HTTP_ADDR`: The external address devices should connect to (default: `127.0.0.1:8080`).
- `RV_BYPASS`: Flag to skip TO1.
- `TO0_ADDR`: Rendezvous server address to register RV blobs (disables self-registration).
- `TO0_GUID`: Device GUID to immediately register an RV blob (requires `TO0_ADDR` flag).
- `UPLOAD_DIR`: The directory path to put file uploads (default: `uploads`).
- `DOWNLOAD_FILES`: Files to use with `fdo.download` FSIM (can be multiple files).
- `UPLOAD_FILES`: Files to use with `fdo.upload` FSIM (can be multiple files).

## Usage

### Building the Docker Image

To build the Docker image, run:

```console
make build
```

### Running the Docker Container
To start the FDO Go service as a Docker container, run:

```console
make run
```
This will start the container with the specified network settings and database path.

### Stoping the Docker Container
To stop the Docker Container, run:
```console
make stop
```

### Default Target
To build and run the Docker container in one step, run:
```console
make all
```

***NOTE:***
Supports all server parameters specified in the building section. Use network mode based on the host machine and requirements.
