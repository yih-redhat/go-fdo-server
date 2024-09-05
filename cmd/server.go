// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"iter"
	"log"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fsim"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

var serverFlags = flag.NewFlagSet("server", flag.ContinueOnError)

var (
	useTLS     bool
	addr       string
	dbPath     string
	dbPass     string
	extAddr    string
	to0Addr    string
	to0Guid    string
	rvBypass   bool
	downloads  stringList
	uploadDir  string
	uploadReqs stringList
)

type stringList []string

func (list *stringList) Set(v string) error {
	*list = append(*list, v)
	return nil
}

func (list *stringList) String() string {
	return fmt.Sprintf("[%s]", strings.Join(*list, ","))
}

func init() {
	serverFlags.StringVar(&dbPath, "db", "", "SQLite database file path")
	serverFlags.StringVar(&dbPass, "db-pass", "", "SQLite database encryption-at-rest passphrase")
	serverFlags.BoolVar(&debug, "debug", debug, "Print HTTP contents")
	serverFlags.StringVar(&to0Addr, "to0", "", "Rendezvous server `addr`ess to register RV blobs (disables self-registration)")
	serverFlags.StringVar(&to0Guid, "to0-guid", "", "Device `guid` to immediately register an RV blob (requires to0 flag)")
	serverFlags.StringVar(&extAddr, "ext-http", "", "External `addr`ess devices should connect to (default \"127.0.0.1:${LISTEN_PORT}\")")
	serverFlags.StringVar(&addr, "http", "localhost:8080", "The `addr`ess to listen on")
	serverFlags.BoolVar(&insecureTLS, "insecure-tls", false, "Listen with a self-signed TLS certificate")
	serverFlags.BoolVar(&rvBypass, "rv-bypass", false, "Skip TO1")
	serverFlags.Var(&downloads, "download", "Use fdo.download FSIM for each `file` (flag may be used multiple times)")
	serverFlags.StringVar(&uploadDir, "upload-dir", "uploads", "The directory `path` to put file uploads")
	serverFlags.Var(&uploadReqs, "upload", "Use fdo.upload FSIM for each `file` (flag may be used multiple times)")
}

// Server represents the HTTP server
type Server struct {
	addr    string
	handler http.Handler
	useTLS  bool
	state   *sqlite.DB
}

// NewServer creates a new Server
func NewServer(addr string, handler http.Handler, useTLS bool, state *sqlite.DB) *Server {
	return &Server{addr: addr, handler: handler, useTLS: useTLS, state: state}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	srv := &http.Server{
		Addr:              s.addr,
		Handler:           s.handler,
		ReadHeaderTimeout: 3 * time.Second,
	}

	// Channel to listen for interrupt or terminate signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// Goroutine to listen for signals and gracefully shut down the server
	go func() {
		<-stop
		slog.Debug("Shutting down server...")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			slog.Debug("Server forced to shutdown:", "err", err)
		}
	}()

	if s.useTLS {
		cert, err := tlsCert(s.state.DB())
		if err != nil {
			return err
		}
		srv.TLSConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{*cert},
		}
		return srv.ListenAndServeTLS("", "")
	}
	return srv.ListenAndServe()
}

func server() error {
	if debug {
		level.Set(slog.LevelDebug)
	}

	if dbPath == "" {
		return errors.New("db flag is required")
	}
	state, err := sqlite.New(dbPath, dbPass)
	if err != nil {
		return err
	}
	state.AutoExtend = true
	state.PreserveReplacedVouchers = true

	useTLS = insecureTLS

	// RV Info
	rvInfo, host, port, err := createRvInfo(useTLS, extAddr, addr)
	if err != nil {
		return err
	}

	// Invoke TO0 client if a GUID is specified
	if to0Guid != "" {
		return registerRvBlob(host, port, state)
	}
	return serveHTTP(rvInfo, state)
}

func serveHTTP(rvInfo [][]fdo.RvInstruction, state *sqlite.DB) error {

	err := initDb(state)
	if err != nil {
		return err
	}

	// Create FDO responder
	svc, err := newService(rvInfo, state)
	if err != nil {
		return err
	}
	svc.OwnerModules = ownerModules

	// Handle messages
	handler := NewHTTPHandler(svc, &rvInfo).RegisterRoutes()
	// Listen and serve
	server := NewServer(addr, handler, useTLS, state)

	slog.Debug("Starting server on:", "addr", addr)
	return server.Start()

}

func registerRvBlob(host string, port uint16, state *sqlite.DB) error {
	if to0Addr == "" {
		return fmt.Errorf("to0-guid depends on to0 flag being set")
	}

	// Parse to0-guid flag
	guidBytes, err := hex.DecodeString(to0Guid)
	if err != nil {
		return fmt.Errorf("error parsing hex GUID of device to register RV blob: %w", err)
	}
	if len(guidBytes) != 16 {
		return fmt.Errorf("error parsing hex GUID of device to register RV blob: must be 16 bytes")
	}
	var guid fdo.GUID
	copy(guid[:], guidBytes)

	proto := fdo.HTTPTransport
	if useTLS {
		proto = fdo.HTTPSTransport
	}

	refresh, err := (&fdo.TO0Client{
		Transport: tlsTransport(nil),
		Addrs: []fdo.RvTO2Addr{
			{
				DNSAddress:        &host,
				Port:              port,
				TransportProtocol: proto,
			},
		},
		Vouchers:  state,
		OwnerKeys: state,
	}).RegisterBlob(context.Background(), to0Addr, guid)
	if err != nil {
		return fmt.Errorf("error performing to0: %w", err)
	}
	slog.Debug("to0 refresh", "duration", time.Duration(refresh)*time.Second)

	return nil
}

func mustMarshal(v any) []byte {
	data, err := cbor.Marshal(v)
	if err != nil {
		panic(err.Error())
	}
	return data
}

//nolint:gocyclo
func newService(rvInfo [][]fdo.RvInstruction, state *sqlite.DB) (*fdo.Server, error) {
	// Auto-register RV blob so that TO1 can be tested
	if to0Addr == "" && !rvBypass {
		to1URLs, _ := fdo.BaseHTTP(rvInfo)
		to1URL, err := url.Parse(to1URLs[0])
		if err != nil {
			return nil, fmt.Errorf("error parsing TO1 URL to use for TO2 addr: %w", err)
		}
		to1Host := to1URL.Hostname()
		to1Port, err := strconv.ParseUint(to1URL.Port(), 10, 16)
		if err != nil {
			return nil, fmt.Errorf("error parsing TO1 port to use for TO2: %w", err)
		}
		proto := fdo.HTTPTransport
		if useTLS {
			proto = fdo.HTTPSTransport
		}

		fakeHash := sha256.Sum256([]byte("fake blob"))
		state.AutoRegisterRV = &fdo.To1d{
			RV: []fdo.RvTO2Addr{
				{
					DNSAddress:        &to1Host,
					Port:              uint16(to1Port),
					TransportProtocol: proto,
				},
			},
			To0dHash: fdo.Hash{
				Algorithm: fdo.Sha256Hash,
				Value:     fakeHash[:],
			},
		}
	}

	// Generate manufacturing component keys
	rsaMfgKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	ec256MfgKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ec384MfgKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	generateCA := func(key crypto.Signer) ([]*x509.Certificate, error) {
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Test CA"},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(30 * 365 * 24 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		return []*x509.Certificate{cert}, nil
	}
	rsaChain, err := generateCA(rsaMfgKey)
	if err != nil {
		return nil, err
	}
	ec256Chain, err := generateCA(ec256MfgKey)
	if err != nil {
		return nil, err
	}
	ec384Chain, err := generateCA(ec384MfgKey)
	if err != nil {
		return nil, err
	}
	if err := state.AddManufacturerKey(fdo.RsaPkcsKeyType, rsaMfgKey, rsaChain); err != nil {
		return nil, err
	}
	if err := state.AddManufacturerKey(fdo.RsaPssKeyType, rsaMfgKey, rsaChain); err != nil {
		return nil, err
	}
	if err := state.AddManufacturerKey(fdo.Secp256r1KeyType, ec256MfgKey, ec256Chain); err != nil {
		return nil, err
	}
	if err := state.AddManufacturerKey(fdo.Secp384r1KeyType, ec384MfgKey, ec384Chain); err != nil {
		return nil, err
	}

	// Generate owner keys
	rsaOwnerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	ec256OwnerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ec384OwnerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := state.AddOwnerKey(fdo.RsaPkcsKeyType, rsaOwnerKey, nil); err != nil {
		return nil, err
	}
	if err := state.AddOwnerKey(fdo.RsaPssKeyType, rsaOwnerKey, nil); err != nil {
		return nil, err
	}
	if err := state.AddOwnerKey(fdo.Secp256r1KeyType, ec256OwnerKey, nil); err != nil {
		return nil, err
	}
	if err := state.AddOwnerKey(fdo.Secp384r1KeyType, ec384OwnerKey, nil); err != nil {
		return nil, err
	}

	return &fdo.Server{
		Tokens:    state,
		DI:        state,
		TO0:       state,
		TO1:       state,
		TO2:       state,
		RVBlobs:   state,
		Vouchers:  state,
		OwnerKeys: state,
		RvInfo:    rvInfo,
	}, nil
}

func ownerModules(ctx context.Context, guid fdo.GUID, info string, chain []*x509.Certificate, devmod fdo.Devmod, modules []string) iter.Seq[serviceinfo.OwnerModule] {
	return func(yield func(serviceinfo.OwnerModule) bool) {
		if slices.Contains(modules, "fdo.download") {
			for _, name := range downloads {
				f, err := os.Open(filepath.Clean(name))
				if err != nil {
					log.Fatalf("error opening %q for download FSIM: %v", name, err)
				}
				defer func() { _ = f.Close() }()

				if !yield(&fsim.DownloadContents[*os.File]{
					Name:         name,
					Contents:     f,
					MustDownload: true,
				}) {
					return
				}
			}
		}

		if slices.Contains(modules, "fdo.upload") {
			for _, name := range uploadReqs {
				if !yield(&fsim.UploadRequest{
					Dir:  uploadDir,
					Name: name,
				}) {
					return
				}
			}
		}
	}
}

func tlsCert(db *sql.DB) (*tls.Certificate, error) {
	// Ensure that the https table exists
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS https
		( cert BLOB NOT NULL
		, key BLOB NOT NULL
		)`); err != nil {
		return nil, err
	}

	// Load a TLS cert and key from the database
	row := db.QueryRow("SELECT cert, key FROM https LIMIT 1")
	var certDer, keyDer []byte
	if err := row.Scan(&certDer, &keyDer); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if len(keyDer) > 0 {
		key, err := x509.ParsePKCS8PrivateKey(keyDer)
		if err != nil {
			return nil, fmt.Errorf("bad HTTPS key stored: %w", err)
		}
		return &tls.Certificate{
			Certificate: [][]byte{certDer},
			PrivateKey:  key,
		}, nil
	}

	// Generate a new self-signed TLS CA
	tlsKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, tlsKey.Public(), tlsKey)
	if err != nil {
		return nil, err
	}
	tlsCA, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	// Store TLS cert and key to the database
	keyDER, err := x509.MarshalPKCS8PrivateKey(tlsKey)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec("INSERT INTO https (cert, key) VALUES (?, ?)", caDER, keyDER); err != nil {
		return nil, err
	}

	// Use CA to serve TLS
	return &tls.Certificate{
		Certificate: [][]byte{tlsCA.Raw},
		PrivateKey:  tlsKey,
	}, nil
}
