# FIDO Device Onboard - Go Server

`go-fdo-server` is a server implementation of FIDO Device Onboard specification in Go.

[fdo]: https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v1.1-20220419/FIDO-Device-Onboard-PS-v1.1-20220419.html
[cbor]: https://www.rfc-editor.org/rfc/rfc8949.html
[cose]: https://datatracker.ietf.org/doc/html/rfc8152

## Building the Example Server Application

The example server application can be built with `go build` directly, but requires a Go workspace to build from the root package directory.

```console
$ go work init
$ go work use -r .
$ go build -o fdo ./cmd
$ ./fdo

Usage:
  fdo [--] [options]

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

### Building FDO container

```console
docker build -t fdo .
```

### Starting FDO Go Service as container

```console
docker run --network=host fdo -db ./test.db --debug
```
***NOTE:***
Supports all server parameters specified in the building section. Use network mode based on the host machine and requirements. 
