// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package main implements client and server modes.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
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
	if err := server(); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(2)
	}

}
