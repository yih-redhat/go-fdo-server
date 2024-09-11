package ownerinfo

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo-server/internal/db"
)

func RetrieveOwnerInfo() ([]fdo.RvTO2Addr, error) {
	ownerData, err := db.FetchData("owner_info")
	if err != nil {
		return nil, fmt.Errorf("error fetching rvData after POST: %w", err)
	}

	parsedData, ok := ownerData.Value.([]interface{})
	if !ok || len(parsedData) == 0 {
		return nil, fmt.Errorf("error parsing ownerData after POST: %v", ownerData.Value)
	}

	rvTO2Addrs, err := ParseRvTO2Addr(parsedData)
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
	}
	return rvTO2Addrs, nil
}

func FetchOwnerInfo() ([]fdo.RvTO2Addr, error) {
	var ownerInfo []fdo.RvTO2Addr

	if exists, err := db.CheckDataExists("owner_info"); err != nil {
		slog.Debug("Error checking ownerInfo existence", "error", err)
		return nil, err
	} else if exists {
		if ownerInfo, err = RetrieveOwnerInfo(); err != nil {
			slog.Debug("Error retrieving ownerInfo", "error", err)
			return nil, err
		}
	} else if !exists {
		return nil, err
	}
	return ownerInfo, nil
}

func ParseRvTO2Addr(ownerData []interface{}) ([]fdo.RvTO2Addr, error) {
	var rvTO2Addrs []fdo.RvTO2Addr
	for _, item := range ownerData {
		itemSlice, ok := item.([]interface{})
		if !ok || len(itemSlice) != 4 {
			return nil, fmt.Errorf("invalid data format")
		}

		ipStr, ok := itemSlice[0].(string)
		if !ok {
			return nil, fmt.Errorf("invalid IP address format")
		}
		ip := net.ParseIP(ipStr)

		dnsStr, ok := itemSlice[1].(string)
		if !ok {
			return nil, fmt.Errorf("invalid DNS address format")
		}

		port, ok := itemSlice[2].(float64)
		if !ok {
			return nil, fmt.Errorf("invalid port format")
		}

		protocol, ok := itemSlice[3].(float64)
		if !ok {
			return nil, fmt.Errorf("invalid transport protocol format")
		}

		rvTO2Addr := fdo.RvTO2Addr{
			IPAddress:         &ip,
			DNSAddress:        &dnsStr,
			Port:              uint16(port),
			TransportProtocol: fdo.TransportProtocol(protocol),
		}
		rvTO2Addrs = append(rvTO2Addrs, rvTO2Addr)
	}

	return rvTO2Addrs, nil
}

func CreateRvTO2Addr(host string, port uint16, useTLS bool) ([]fdo.RvTO2Addr, error) {
	var rvTO2Addrs []fdo.RvTO2Addr
	var rvTO2Addr fdo.RvTO2Addr
	ip := net.ParseIP(host)

	var protocol fdo.TransportProtocol
	if useTLS {
		protocol = fdo.HTTPSTransport
	} else {
		protocol = fdo.HTTPTransport
	}

	if ip != nil {
		rvTO2Addr = fdo.RvTO2Addr{
			IPAddress:         &ip,
			DNSAddress:        nil,
			Port:              port,
			TransportProtocol: protocol,
		}
	} else {
		rvTO2Addr = fdo.RvTO2Addr{
			IPAddress:         nil,
			DNSAddress:        &host,
			Port:              port,
			TransportProtocol: protocol,
		}
	}
	rvTO2Addrs = append(rvTO2Addrs, rvTO2Addr)

	return rvTO2Addrs, nil
}
