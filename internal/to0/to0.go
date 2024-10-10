// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package to0

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo-server/internal/ownerinfo"
	"github.com/fido-device-onboard/go-fdo-server/internal/rvinfo"
	"github.com/fido-device-onboard/go-fdo-server/internal/tls"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

func RegisterRvBlob(RvInfo [][]protocol.RvInstruction, to0Guid string, state *sqlite.DB) error {

	to0Addr, err := rvinfo.GetRVIPAddress(RvInfo)
	if err != nil {
		fmt.Println("Error:", err)
		return fmt.Errorf("error parsing TO0 Address from RV Info: %w", err)
	}

	// Parse to0-guid flag
	guidBytes, err := hex.DecodeString(to0Guid)
	if err != nil {
		return fmt.Errorf("error parsing hex GUID of device to register RV blob: %w", err)
	}
	if len(guidBytes) != 16 {
		return fmt.Errorf("error parsing hex GUID of device to register RV blob: must be 16 bytes")
	}
	var guid protocol.GUID
	copy(guid[:], guidBytes)

	// Retrieve owner info from DB
	to2Addrs, err := ownerinfo.FetchOwnerInfo()
	if err != nil {
		return fmt.Errorf("error fetching ownerinfo: %w", err)
	}

	refresh, err := (&fdo.TO0Client{
		Vouchers:  state,
		OwnerKeys: state,
	}).RegisterBlob(context.Background(), tls.TlsTransport(to0Addr, nil, false), guid, to2Addrs)
	if err != nil {
		return fmt.Errorf("error performing to0: %w", err)
	}
	slog.Debug("to0 refresh", "duration", time.Duration(refresh)*time.Second)

	return nil
}
