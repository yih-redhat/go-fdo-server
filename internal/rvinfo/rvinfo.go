// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package rvinfo

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo-server/internal/db"
	"github.com/fido-device-onboard/go-fdo-server/internal/utils"
)

func CreateRvInfo(useTLS bool, extAddr, addr string, rvBypass bool) ([][]fdo.RvInstruction, string, uint16, error) {
	prot := fdo.RVProtHTTP
	if useTLS {
		prot = fdo.RVProtHTTPS
	}
	rvInfo := [][]fdo.RvInstruction{{{Variable: fdo.RVProtocol, Value: utils.MustMarshal(prot)}}}
	if extAddr == "" {
		extAddr = addr
	}

	host, portStr, err := net.SplitHostPort(extAddr)
	if err != nil {
		return nil, "", 0, fmt.Errorf("invalid external addr: %w", err)
	}

	if host == "" {
		rvInfo[0] = append(rvInfo[0], fdo.RvInstruction{Variable: fdo.RVIPAddress, Value: utils.MustMarshal(net.IP{127, 0, 0, 1})})
	} else if hostIP := net.ParseIP(host); hostIP.To4() != nil || hostIP.To16() != nil {
		rvInfo[0] = append(rvInfo[0], fdo.RvInstruction{Variable: fdo.RVIPAddress, Value: utils.MustMarshal(hostIP)})
	} else {
		rvInfo[0] = append(rvInfo[0], fdo.RvInstruction{Variable: fdo.RVDns, Value: utils.MustMarshal(host)})
	}

	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, "", 0, fmt.Errorf("invalid external port: %w", err)
	}
	port := uint16(portNum)
	rvInfo[0] = append(rvInfo[0], fdo.RvInstruction{Variable: fdo.RVDevPort, Value: utils.MustMarshal(port)})

	if rvBypass {
		rvInfo[0] = append(rvInfo[0], fdo.RvInstruction{Variable: fdo.RVBypass})
	}

	return rvInfo, host, port, nil
}

func UpdateRvInfoFromDB(rvInfo *[][]fdo.RvInstruction) error {
	rvData, err := db.FetchDataFromDB()
	if err != nil {
		return fmt.Errorf("error fetching rvData after POST: %w", err)
	}

	parsedData, ok := rvData.Value.([]interface{})
	if !ok || len(parsedData) == 0 {
		return fmt.Errorf("error parsing rvData after POST: %v", rvData.Value)
	}

	for rvDirectiveIndex, rvDirective := range parsedData {
		rvMap, err := ParseRvMap(rvDirectiveIndex, rvDirective)
		if err != nil {
			slog.Debug("Error parsing item", "index", rvDirectiveIndex, "error", err)
			continue
		}
		if err := UpdateRvInfo(rvInfo, rvDirectiveIndex, rvMap); err != nil {
			return fmt.Errorf("error updating RVInfo: %w", err)
		}
	}
	return nil
}

func ParseRvMap(rvDirectiveIndex int, rvDirective interface{}) (map[fdo.RvVar]interface{}, error) {
	rvMap := make(map[fdo.RvVar]interface{})
	nestedItems, ok := rvDirective.([]interface{})
	if !ok {
		return nil, fmt.Errorf("error parsing item: %v", rvDirective)
	}
	for rvPairIndex, rvPair := range nestedItems {
		keyValue, ok := rvPair.([]interface{})
		if !ok || len(keyValue) != 2 {
			return nil, fmt.Errorf("error parsing pair %d in item: %v", rvPairIndex, rvPair)
		}
		key := keyValue[0]
		value := keyValue[1]

		keyRvVar, ok := key.(float64)
		if !ok {
			return nil, fmt.Errorf("error converting key to float64 in pair %d: %v", rvPairIndex, key)
		}

		rvMap[fdo.RvVar(keyRvVar)] = value
		utils.LogRvVar(rvDirectiveIndex, fdo.RvVar(keyRvVar), value)
	}
	return rvMap, nil
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
		newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVProtocol, Value: utils.MustMarshal(fdo.RVProtHTTP)})
	} else {
		isHttp := fdo.RvProt(rvMap[fdo.RVProtocol].(float64))
		if isHttp == fdo.RVProtHTTP {
			newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVProtocol, Value: utils.MustMarshal(fdo.RVProtHTTP)})
		} else {
			newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVProtocol, Value: utils.MustMarshal(fdo.RVProtHTTPS)})
		}
	}

	host := rvMap[fdo.RVIPAddress].(string)
	if host == "" {
		newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVIPAddress, Value: utils.MustMarshal(net.IP{127, 0, 0, 1})})
	} else if hostIP := net.ParseIP(host); hostIP.To4() != nil || hostIP.To16() != nil {
		newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVIPAddress, Value: utils.MustMarshal(hostIP)})
	} else {
		newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVDns, Value: utils.MustMarshal(host)})
	}

	if rvMap[fdo.RVDevPort] != nil {
		newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVDevPort, Value: utils.MustMarshal(uint16(rvMap[fdo.RVDevPort].(float64)))})
	}

	if rvMap[fdo.RVOwnerPort] != nil {
		newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVOwnerPort, Value: utils.MustMarshal(uint16(rvMap[fdo.RVOwnerPort].(float64)))})
	}

	if rvMap[fdo.RVDelaysec] != nil {
		newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVDelaysec, Value: utils.MustMarshal(uint16(rvMap[fdo.RVDelaysec].(float64)))})
	}

	if rvMap[fdo.RVBypass] == nil {
		newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVBypass, Value: utils.MustMarshal(false)})
	} else {
		rvBypass := rvMap[fdo.RVBypass].(bool)
		if rvBypass {
			newRvInfo[index] = append(newRvInfo[index], fdo.RvInstruction{Variable: fdo.RVBypass})
		}
	}

	*rvInfo = newRvInfo

	return nil
}
