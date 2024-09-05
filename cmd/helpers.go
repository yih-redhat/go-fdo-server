package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

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

var mu sync.Mutex
var db *sql.DB

func initDb(state *sqlite.DB) {
	db = state.DB()
}

func fetchVoucher(guid []byte) (Voucher, error) {
	var voucher Voucher
	err := db.QueryRow("SELECT guid, cbor FROM vouchers WHERE guid = ?", guid).Scan(&voucher.GUID, &voucher.CBOR)
	return voucher, err
}

func fetchOwnerKeys() ([]OwnerKey, error) {
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

func insertVoucher(voucher Voucher) error {
	_, err := db.Exec("INSERT INTO vouchers (guid, cbor) VALUES (?, ?)", voucher.GUID, voucher.CBOR)
	return err
}

func updateOwnerKeys(ownerKeys []OwnerKey) error {
	for _, ownerKey := range ownerKeys {
		_, err := db.Exec("UPDATE owner_keys SET pkcs8 = ?, x509_chain = ? WHERE type = ?", ownerKey.PKCS8, ownerKey.X509Chain, ownerKey.Type)
		if err != nil {
			return err
		}
	}
	return nil
}

func parseRequestBody(r *http.Request) (Data, error) {
	var data Data
	contentType := r.Header.Get("Content-Type")
	if contentType == "text/plain" {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return data, fmt.Errorf("error reading body: %w", err)
		}
		var rawData interface{}
		if err := json.Unmarshal(body, &rawData); err != nil {
			return data, fmt.Errorf("error unmarshalling body: %w", err)
		}
		data.Value = rawData
	} else {
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			return data, fmt.Errorf("error decoding JSON: %w", err)
		}
	}
	return data, nil
}

func checkDataExists() (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM rvinfo WHERE id = 1").Scan(&count)
	if err != nil {
		return false, fmt.Errorf("error counting rows: %w", err)
	}
	return count > 0, nil
}

func insertData(data Data) error {
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

func updateRvInfoFromDB(rvInfo *[][]fdo.RvInstruction) error {
	data, err := fetchDataFromDB()
	if err != nil {
		return fmt.Errorf("error fetching data after POST: %w", err)
	}

	parsedData, ok := data.Value.([]interface{})
	if !ok || len(parsedData) == 0 {
		return fmt.Errorf("error parsing data after POST: %v", data.Value)
	}

	for i, item := range parsedData {
		rvMap, err := parseRvMap(i, item)
		if err != nil {
			log.Printf("Error parsing item %d: %v", i, err)
			continue
		}
		if err := UpdateRvInfo(rvInfo, i, rvMap); err != nil {
			return fmt.Errorf("error updating RVInfo: %w", err)
		}
	}
	return nil
}

func parseRvMap(index int, item interface{}) (map[fdo.RvVar]interface{}, error) {
	rvMap := make(map[fdo.RvVar]interface{})
	nestedItems, ok := item.([]interface{})
	if !ok {
		return nil, fmt.Errorf("error parsing item: %v", item)
	}
	for j, pair := range nestedItems {
		keyValue, ok := pair.([]interface{})
		if !ok || len(keyValue) != 2 {
			return nil, fmt.Errorf("error parsing pair %d in item: %v", j, pair)
		}
		key := keyValue[0]
		value := keyValue[1]

		keyRvVar, ok := key.(float64)
		if !ok {
			return nil, fmt.Errorf("error converting key to float64 in pair %d: %v", j, key)
		}

		rvMap[fdo.RvVar(keyRvVar)] = value
		logRvVar(index, fdo.RvVar(keyRvVar), value)
	}
	return rvMap, nil
}

func logRvVar(index int, key fdo.RvVar, value interface{}) {
	switch key {
	case fdo.RVDevOnly:
		log.Printf("RV %d -> Key: RVDevOnly, Value: %v", index, value)
	case fdo.RVOwnerOnly:
		log.Printf("RV %d -> Key: RVOwnerOnly, Value: %v", index, value)
	case fdo.RVIPAddress:
		log.Printf("RV %d -> Key: RVIPAddress, Value: %v", index, value)
	case fdo.RVDevPort:
		log.Printf("RV %d -> Key: RVDevPort, Value: %v", index, value)
	case fdo.RVOwnerPort:
		log.Printf("RV %d -> Key: RVOwnerPort, Value: %v", index, value)
	case fdo.RVDns:
		log.Printf("RV %d -> Key: RVDns, Value: %v", index, value)
	case fdo.RVSvCertHash:
		log.Printf("RV %d -> Key: RVSvCertHash, Value: %v", index, value)
	case fdo.RVClCertHash:
		log.Printf("RV %d -> Key: RVClCertHash, Value: %v", index, value)
	case fdo.RVUserInput:
		log.Printf("RV %d -> Key: RVUserInput, Value: %v", index, value)
	case fdo.RVWifiSsid:
		log.Printf("RV %d -> Key: RVWifiSsid, Value: %v", index, value)
	case fdo.RVWifiPw:
		log.Printf("RV %d -> Key: RVWifiPw, Value: %v", index, value)
	case fdo.RVMedium:
		log.Printf("RV %d -> Key: RVMedium, Value: %v", index, value)
	case fdo.RVProtocol:
		log.Printf("RV %d -> Key: RVProtocol, Value: %v", index, value)
	case fdo.RVDelaysec:
		log.Printf("RV %d -> Key: RVDelaysec, Value: %v", index, value)
	case fdo.RVBypass:
		log.Printf("RV %d -> Key: RVBypass, Value: %v", index, value)
	case fdo.RVExtRV:
		log.Printf("RV %d -> Key: RVExtRV, Value: %v", index, value)
	default:
		log.Printf("Item %d - Key: %v, Value: %v", index, key, value)
	}
}

func updateDataInDB(data Data) error {
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

func fetchDataFromDB() (Data, error) {
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

func UpdateRvInfo(rvInfo *[][]fdo.RvInstruction, index int, rvMap map[fdo.RvVar]interface{}) error {
	var newRvInfo [][]fdo.RvInstruction

	if index > 0 {
		newRvInfo = make([][]fdo.RvInstruction, len(*rvInfo))
		copy(newRvInfo, *rvInfo)
	}

	for len(newRvInfo) <= index {
		newRvInfo = append(newRvInfo, make([]fdo.RvInstruction, 0))
	}

	if rvMap[fdo.RVProtocol] == nil {
		newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVProtocol, Value: mustMarshal(fdo.RVProtHTTP)})
	} else {
		isHttp := fdo.RvProt(rvMap[fdo.RVProtocol].(float64))
		if isHttp == fdo.RVProtHTTP {
			newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVProtocol, Value: mustMarshal(fdo.RVProtHTTP)})
		} else {
			newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVProtocol, Value: mustMarshal(fdo.RVProtHTTPS)})
		}
	}

	host := rvMap[fdo.RVIPAddress].(string)
	if host == "" {
		newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVIPAddress, Value: mustMarshal(net.IP{127, 0, 0, 1})})
	} else if hostIP := net.ParseIP(host); hostIP.To4() != nil || hostIP.To16() != nil {
		newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVIPAddress, Value: mustMarshal(hostIP)})
	} else {
		newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVDns, Value: mustMarshal(host)})
	}

	if rvMap[fdo.RVDevPort] != nil {
		newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVDevPort, Value: mustMarshal(uint16(rvMap[fdo.RVDevPort].(float64)))})
	}

	if rvMap[fdo.RVOwnerPort] != nil {
		newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVOwnerPort, Value: mustMarshal(uint16(rvMap[fdo.RVOwnerPort].(float64)))})
	}

	if rvMap[fdo.RVDelaysec] != nil {
		newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVDelaysec, Value: mustMarshal(uint16(rvMap[fdo.RVDelaysec].(float64)))})
	}

	if rvMap[fdo.RVBypass] == nil {
		newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVBypass, Value: mustMarshal(false)})
	} else {
		rvBypass := rvMap[fdo.RVBypass].(bool)
		if rvBypass {
			newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVBypass})
		}
	}

	*rvInfo = newRvInfo

	return nil
}
