// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package db

type Data struct {
	Value interface{} `json:"value"`
}

type Voucher struct {
	GUID []byte `json:"guid"`
	CBOR []byte `json:"cbor"`
}

type OwnerKey struct {
	Type      int    `json:"type"`
	PKCS8     []byte `json:"pkcs8"`
	X509Chain []byte `json:"x509_chain"`
}
