// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package main implements client and server modes.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

var flags = flag.NewFlagSet("root", flag.ContinueOnError)

var (
	debug bool
)

func init() {
	flags.BoolVar(&debug, "debug", false, "Run subcommand with debug enabled")
}

func usage() {
	fmt.Fprintf(os.Stderr, `
Usage:
  fdo [global_options] [--] [options]

Global options:
%s
Server options:
%s`, options(flags), options(serverFlags))
}

func options(flags *flag.FlagSet) string {
	oldOutput := flags.Output()
	defer flags.SetOutput(oldOutput)

	var buf bytes.Buffer
	flags.SetOutput(&buf)
	flags.PrintDefaults()

	return buf.String()
}

func main() {
	if err := flags.Parse(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		usage()
		os.Exit(1)
	}

	var args []string
	if flags.NArg() > 1 {
		args = flags.Args()[1:]
		if flags.Arg(1) == "--" {
			args = flags.Args()[2:]
		}
	}

	if err := serverFlags.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		usage()
		os.Exit(1)
	}

	if err := validateFlags(); err != nil {
		fmt.Fprintf(os.Stderr, "Validation error: %v\n", err)
		os.Exit(1)
	}

	if err := server(); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(2)
	}

}

func validateFlags() error {
	if dbPath != "" && !isValidPath(dbPath) {
		return fmt.Errorf("invalid database path: %s", dbPath)
	}

	if extAddr != "" {
		scheme := "http"
		if insecureTLS {
			scheme = "https"
		}
		fullURL := scheme + "://" + extAddr
		parsedURL, err := url.ParseRequestURI(fullURL)
		if err != nil {
			return fmt.Errorf("invalid external address: %s", extAddr)
		}
		host, port, err := net.SplitHostPort(parsedURL.Host)
		if err != nil {
			return fmt.Errorf("invalid external address: %s", extAddr)
		}
		if net.ParseIP(host) == nil && !isValidHostname(host) {
			return fmt.Errorf("invalid external hostname: %s", host)
		}
		if port != "" && !isValidPort(port) {
			return fmt.Errorf("invalid external port: %s", port)
		}
	}

	if addr != "" {
		scheme := "http"
		if insecureTLS {
			scheme = "https"
		}
		fullURL := scheme + "://" + addr
		parsedURL, err := url.ParseRequestURI(fullURL)
		if err != nil {
			return fmt.Errorf("invalid address: %s", addr)
		}
		host, port, err := net.SplitHostPort(parsedURL.Host)
		if err != nil {
			return fmt.Errorf("invalid address: %s", addr)
		}
		if net.ParseIP(host) == nil && !isValidHostname(host) {
			return fmt.Errorf("invalid hostname: %s", host)
		}
		if port != "" && !isValidPort(port) {
			return fmt.Errorf("invalid port: %s", port)
		}
	}

	if resaleKey != "" && (!isValidPath(resaleKey) || !fileExists(resaleKey)) {
		return fmt.Errorf("invalid resale key path: %s", resaleKey)
	}

	if serverCertPath != "" && !isValidPath(serverCertPath) {
		return fmt.Errorf("invalid server certificate path: %s", serverCertPath)
	}

	if serverKeyPath != "" && !isValidPath(serverKeyPath) {
		return fmt.Errorf("invalid server key path: %s", serverKeyPath)
	}

	if importVoucher != "" && !isValidPath(importVoucher) {
		return fmt.Errorf("invalid import voucher path: %s", importVoucher)
	}

	if uploadDir != "" && (!isValidPath(uploadDir)) {
		return fmt.Errorf("invalid upload directory path: %s", uploadDir)
	}

	for _, path := range downloads {
		if !isValidPath(path) {
			return fmt.Errorf("invalid download path: %s", path)
		}

		if !fileExists(path) {
			return fmt.Errorf("file doesn't exist: %s", path)
		}
	}

	for _, path := range wgets {
		if _, err := url.ParseRequestURI(path); err != nil {
			return fmt.Errorf("invalid wget URL: %s", path)
		}
	}

	return nil
}

func isValidPath(p string) bool {
	if p == "" {
		return false
	}
	absPath, err := filepath.Abs(p)
	return err == nil && absPath != ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !os.IsNotExist(err)
}

func isValidHostname(hostname string) bool {
	if len(hostname) > 255 {
		return false
	}
	for _, part := range strings.Split(hostname, ".") {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		for _, char := range part {
			if !((char >= 'a' && char <= 'z') ||
				(char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9') ||
				char == '-') {
				return false
			}
		}
		if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
	}
	return true
}

func isValidPort(port string) bool {
	for _, char := range port {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
