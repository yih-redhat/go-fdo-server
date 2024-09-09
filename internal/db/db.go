// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/fido-device-onboard/go-fdo/sqlite"
)

var db *sql.DB

func InitDb(state *sqlite.DB) error {
	db = state.DB()
	if err := createRvTable(); err != nil {
		slog.Error("Failed to create table")
		return err
	}
	return nil
}

func createRvTable() error {
	query := `CREATE TABLE IF NOT EXISTS rvinfo (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		value TEXT
	);`
	_, err := db.Exec(query)
	if err != nil {
		return err
	}
	return nil
}

func FetchVoucher(guid []byte) (Voucher, error) {
	var voucher Voucher
	err := db.QueryRow("SELECT guid, cbor FROM vouchers WHERE guid = ?", guid).Scan(&voucher.GUID, &voucher.CBOR)
	return voucher, err
}

func FetchOwnerKeys() ([]OwnerKey, error) {
	rows, err := db.Query("SELECT type, pkcs8, x509_chain FROM owner_keys")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ownerKeys []OwnerKey
	for rows.Next() {
		var ownerKey OwnerKey
		if err := rows.Scan(&ownerKey.Type, &ownerKey.PKCS8, &ownerKey.X509Chain); err != nil {
			return nil, err
		}
		ownerKeys = append(ownerKeys, ownerKey)
	}
	return ownerKeys, nil
}

func InsertVoucher(voucher Voucher) error {
	_, err := db.Exec("INSERT INTO vouchers (guid, cbor) VALUES (?, ?)", voucher.GUID, voucher.CBOR)
	return err
}

func UpdateOwnerKeys(ownerKeys []OwnerKey) error {
	for _, ownerKey := range ownerKeys {
		_, err := db.Exec("UPDATE owner_keys SET pkcs8 = ?, x509_chain = ? WHERE type = ?", ownerKey.PKCS8, ownerKey.X509Chain, ownerKey.Type)
		if err != nil {
			return err
		}
	}
	return nil
}

func CheckRvDataExists() (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM rvinfo WHERE id = 1").Scan(&count)
	if err != nil {
		return false, fmt.Errorf("error counting rows: %w", err)
	}
	return count > 0, nil
}

func InsertRvData(data Data) error {
	value, err := json.Marshal(data.Value)
	if err != nil {
		return fmt.Errorf("error marshalling value: %w", err)
	}
	_, err = db.Exec("INSERT INTO rvinfo (id, value) VALUES (1, ?)", string(value))
	if err != nil {
		return fmt.Errorf("error inserting data: %w", err)
	}
	return nil
}

func UpdateRvDataInDB(data Data) error {
	value, err := json.Marshal(data.Value)
	if err != nil {
		return fmt.Errorf("error marshalling value: %w", err)
	}
	_, err = db.Exec("UPDATE rvinfo SET value = ? WHERE id = 1", string(value))
	if err != nil {
		return fmt.Errorf("error updating data: %w", err)
	}
	return nil
}

func FetchRvData() (Data, error) {
	var data Data
	var value string
	err := db.QueryRow("SELECT value FROM rvinfo WHERE id = 1").Scan(&value)
	if err != nil {
		return data, err
	}

	if err := json.Unmarshal([]byte(value), &data.Value); err != nil {
		return data, err
	}

	return data, nil
}
