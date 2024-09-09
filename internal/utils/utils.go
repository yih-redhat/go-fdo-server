// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package utils

import (
	"log/slog"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
)

func MustMarshal(v any) []byte {
	data, err := cbor.Marshal(v)
	if err != nil {
		panic(err.Error())
	}
	return data
}

func LogRvVar(index int, key fdo.RvVar, value interface{}) {
	switch key {
	case fdo.RVDevOnly:
		slog.Debug("RV ->", "index", index, "key", "RVDevOnly", "value", value)
	case fdo.RVOwnerOnly:
		slog.Debug("RV ->", "index", index, "key", "RVOwnerOnly", "value", value)
	case fdo.RVIPAddress:
		slog.Debug("RV ->", "index", index, "key", "RVIPAddress", "value", value)
	case fdo.RVDevPort:
		slog.Debug("RV ->", "index", index, "key", "RVDevPort", "value", value)
	case fdo.RVOwnerPort:
		slog.Debug("RV ->", "index", index, "key", "RVOwnerPort", "value", value)
	case fdo.RVDns:
		slog.Debug("RV ->", "index", index, "key", "RVDns", "value", value)
	case fdo.RVSvCertHash:
		slog.Debug("RV ->", "index", index, "key", "RVSvCertHash", "value", value)
	case fdo.RVClCertHash:
		slog.Debug("RV ->", "index", index, "key", "RVClCertHash", "value", value)
	case fdo.RVUserInput:
		slog.Debug("RV ->", "index", index, "key", "RVUserInput", "value", value)
	case fdo.RVWifiSsid:
		slog.Debug("RV ->", "index", index, "key", "RVWifiSsid", "value", value)
	case fdo.RVWifiPw:
		slog.Debug("RV ->", "index", index, "key", "RVWifiPw", "value", value)
	case fdo.RVMedium:
		slog.Debug("RV ->", "index", index, "key", "RVMedium", "value", value)
	case fdo.RVProtocol:
		slog.Debug("RV ->", "index", index, "key", "RVProtocol", "value", value)
	case fdo.RVDelaysec:
		slog.Debug("RV ->", "index", index, "key", "RVDelaysec", "value", value)
	case fdo.RVBypass:
		slog.Debug("RV ->", "index", index, "key", "RVBypass", "value", value)
	case fdo.RVExtRV:
		slog.Debug("RV ->", "index", index, "key", "RVExtRV", "value", value)
	default:
		slog.Debug("RV ->", "index", index, "key", key, "value", value)
	}
}
