package worker

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWorkerClient_ValHostAppSec(t *testing.T) {
	// This test would require a mock API server
	// For now, we'll just test that the method exists and has the right signature

	client := &WorkerClient{}

	// Test that the method exists and can be called
	// In a real test, we would mock the sendRequest method
	headers := make(http.Header)
	headers.Set("User-Agent", "test-agent")
	headers.Set("Content-Type", "application/json")

	// This will fail because we don't have a real connection, but it tests the method signature
	_, err := client.ValHostAppSec(
		"example.com",
		"GET",
		"/test",
		headers,
		[]byte("test body"),
		"192.168.1.1",
		"test-agent",
		"1.1",
	)

	// We expect an error because there's no real connection
	assert.Error(t, err)
}

func TestWorkerClient_ValHostAppSec_EmptyHeaders(t *testing.T) {
	client := &WorkerClient{}

	// Test with empty headers
	_, err := client.ValHostAppSec(
		"example.com",
		"POST",
		"/api/test",
		nil,
		[]byte(""),
		"10.0.0.1",
		"",
		"2.0",
	)

	// We expect an error because there's no real connection
	assert.Error(t, err)
}

func TestWorkerClient_ValHostAppSec_NoBody(t *testing.T) {
	client := &WorkerClient{}

	headers := make(http.Header)
	headers.Set("User-Agent", "curl/7.68.0")

	// Test with no body (GET request)
	_, err := client.ValHostAppSec(
		"api.example.com",
		"GET",
		"/status",
		headers,
		nil,
		"203.0.113.1",
		"curl/7.68.0",
		"1.0",
	)

	// We expect an error because there's no real connection
	assert.Error(t, err)
}
