# Copyright 2024 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o fdo ./cmd

# Start a new stage from scratch
FROM scratch

WORKDIR /app
COPY --from=builder /app/fdo /app/fdo

ENTRYPOINT ["./fdo server "]
CMD []