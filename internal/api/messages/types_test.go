package messages

import (
	"bytes"
	"encoding/gob"
	"testing"
)

func TestWorkerRequestEncoding(t *testing.T) {
	// Register types
	RegisterGobTypes()

	// Test encoding and decoding a simple IP request
	originalReq := WorkerRequest{
		Command: GetIP,
		Data: IPRequest{
			IP: "192.168.1.1",
		},
	}

	// Encode
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(originalReq)
	if err != nil {
		t.Fatalf("Failed to encode request: %v", err)
	}

	// Decode
	decoder := gob.NewDecoder(&buf)
	var decodedReq WorkerRequest
	err = decoder.Decode(&decodedReq)
	if err != nil {
		t.Fatalf("Failed to decode request: %v", err)
	}

	// Verify
	if decodedReq.Command != GetIP {
		t.Errorf("Expected command %s, got %s", GetIP, decodedReq.Command)
	}

	ipReq, ok := decodedReq.Data.(IPRequest)
	if !ok {
		t.Fatalf("Expected IPRequest, got %T", decodedReq.Data)
	}

	if ipReq.IP != "192.168.1.1" {
		t.Errorf("Expected IP 192.168.1.1, got %s", ipReq.IP)
	}
}

func TestHostCookieRequestEncoding(t *testing.T) {
	// Register types
	RegisterGobTypes()

	// Test encoding and decoding a host cookie request
	originalReq := WorkerRequest{
		Command: GetHostCookie,
		Data: HostCookieRequest{
			Host: "example.com",
			SSL:  true,
		},
	}

	// Encode
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(originalReq)
	if err != nil {
		t.Fatalf("Failed to encode request: %v", err)
	}

	// Decode
	decoder := gob.NewDecoder(&buf)
	var decodedReq WorkerRequest
	err = decoder.Decode(&decodedReq)
	if err != nil {
		t.Fatalf("Failed to decode request: %v", err)
	}

	// Verify
	if decodedReq.Command != GetHostCookie {
		t.Errorf("Expected command %s, got %s", GetHostCookie, decodedReq.Command)
	}

	cookieReq, ok := decodedReq.Data.(HostCookieRequest)
	if !ok {
		t.Fatalf("Expected HostCookieRequest, got %T", decodedReq.Data)
	}

	if cookieReq.Host != "example.com" {
		t.Errorf("Expected host example.com, got %s", cookieReq.Host)
	}

	if !cookieReq.SSL {
		t.Error("Expected SSL to be true")
	}
}

func TestAppSecRequestEncoding(t *testing.T) {
	// Register types
	RegisterGobTypes()

	// Test encoding and decoding an AppSec request with binary data
	originalReq := WorkerRequest{
		Command: ValHostAppSec,
		Data: AppSecRequest{
			Host:     "api.example.com",
			Method:   "POST",
			URL:      "/api/upload",
			Body:     []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, // PNG header
			RemoteIP: "10.0.0.1",
		},
	}

	// Encode
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(originalReq)
	if err != nil {
		t.Fatalf("Failed to encode request: %v", err)
	}

	// Decode
	decoder := gob.NewDecoder(&buf)
	var decodedReq WorkerRequest
	err = decoder.Decode(&decodedReq)
	if err != nil {
		t.Fatalf("Failed to decode request: %v", err)
	}

	// Verify
	if decodedReq.Command != ValHostAppSec {
		t.Errorf("Expected command %s, got %s", ValHostAppSec, decodedReq.Command)
	}

	appSecReq, ok := decodedReq.Data.(AppSecRequest)
	if !ok {
		t.Fatalf("Expected AppSecRequest, got %T", decodedReq.Data)
	}

	if appSecReq.Host != "api.example.com" {
		t.Errorf("Expected host api.example.com, got %s", appSecReq.Host)
	}

	if appSecReq.Method != "POST" {
		t.Errorf("Expected method POST, got %s", appSecReq.Method)
	}

	if !bytes.Equal(appSecReq.Body, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}) {
		t.Errorf("Binary body data was corrupted")
	}
}

func TestCommandFromString(t *testing.T) {
	cmd := CommandFromString("get:ip")
	if cmd != GetIP {
		t.Errorf("Expected %s, got %s", GetIP, cmd)
	}

	if cmd.String() != "get:ip" {
		t.Errorf("Expected 'get:ip', got %s", cmd.String())
	}
}
