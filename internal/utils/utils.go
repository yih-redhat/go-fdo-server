// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package utils

import (
	"log/slog"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

func MustMarshal(v any) []byte {
	data, err := cbor.Marshal(v)
	if err != nil {
		panic(err.Error())
	}
	return data
}

func LogRvVar(index int, key protocol.RvVar, value interface{}) {
	switch key {
	case protocol.RVDevOnly:
		slog.Debug("RV ->", "index", index, "key", "RVDevOnly", "value", value)
	case protocol.RVOwnerOnly:
		slog.Debug("RV ->", "index", index, "key", "RVOwnerOnly", "value", value)
	case protocol.RVIPAddress:
		slog.Debug("RV ->", "index", index, "key", "RVIPAddress", "value", value)
	case protocol.RVDevPort:
		slog.Debug("RV ->", "index", index, "key", "RVDevPort", "value", value)
	case protocol.RVOwnerPort:
		slog.Debug("RV ->", "index", index, "key", "RVOwnerPort", "value", value)
	case protocol.RVDns:
		slog.Debug("RV ->", "index", index, "key", "RVDns", "value", value)
	case protocol.RVSvCertHash:
		slog.Debug("RV ->", "index", index, "key", "RVSvCertHash", "value", value)
	case protocol.RVClCertHash:
		slog.Debug("RV ->", "index", index, "key", "RVClCertHash", "value", value)
	case protocol.RVUserInput:
		slog.Debug("RV ->", "index", index, "key", "RVUserInput", "value", value)
	case protocol.RVWifiSsid:
		slog.Debug("RV ->", "index", index, "key", "RVWifiSsid", "value", value)
	case protocol.RVWifiPw:
		slog.Debug("RV ->", "index", index, "key", "RVWifiPw", "value", value)
	case protocol.RVMedium:
		slog.Debug("RV ->", "index", index, "key", "RVMedium", "value", value)
	case protocol.RVProtocol:
		slog.Debug("RV ->", "index", index, "key", "RVProtocol", "value", value)
	case protocol.RVDelaysec:
		slog.Debug("RV ->", "index", index, "key", "RVDelaysec", "value", value)
	case protocol.RVBypass:
		slog.Debug("RV ->", "index", index, "key", "RVBypass", "value", value)
	case protocol.RVExtRV:
		slog.Debug("RV ->", "index", index, "key", "RVExtRV", "value", value)
	default:
		slog.Debug("RV ->", "index", index, "key", key, "value", value)
	}
}
