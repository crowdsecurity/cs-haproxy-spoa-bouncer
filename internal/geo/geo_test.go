package geo

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCityAndASN(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g := &GeoDatabase{
		ASNPath:  filepath.Join("test_data", "GeoLite2-ASN.mmdb"),
		CityPath: filepath.Join("test_data", "GeoLite2-City.mmdb"),
	}

	g.Init(ctx)

	// Verify Init succeeded
	assert.True(t, g.IsValid(), "GeoDatabase should be valid after successful Init")

	ip := netip.MustParseAddr("2.125.160.216")
	city, err := g.GetCity(ip)
	if err != nil {
		t.Fatalf("GetCity returned error: %v", err)
	}

	// v2: Names is a struct with fields (English, German, etc.) instead of a map
	cityName := city.City.Names.English
	assert.Equal(t, "Boxford", cityName, "Expected city name 'Boxford', got '%s'", cityName)
	continentName := city.Continent.Names.English
	assert.Equal(t, "Europe", continentName, "Expected continent name 'Europe', got '%s'", continentName)

	ip = netip.MustParseAddr("1.0.0.1")
	asn, err := g.GetASN(ip)
	if err != nil {
		t.Fatalf("GetASN returned error: %v", err)
	}
	assert.Equal(t, uint(15169), asn.AutonomousSystemNumber, "Expected ASN 15169, got %d", asn.AutonomousSystemNumber)
	t.Logf("ASN: %+v", asn)

	ip = netip.MustParseAddr("1.1.1.1")
	city, err = g.GetCity(ip)
	if err != nil {
		t.Fatalf("GetCity returned error: %v", err)
	}
	// v2: Names is a struct with fields, check English field
	cityName = city.City.Names.English
	assert.Empty(t, cityName, "Expected empty city name, got '%s'", cityName)
	continentName = city.Continent.Names.English
	assert.Empty(t, continentName, "Expected empty continent name, got '%s'", continentName)
}

func TestInit_EmptyPaths(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g := &GeoDatabase{
		ASNPath:  "",
		CityPath: "",
	}

	g.Init(ctx)

	// Should be invalid when both paths are empty
	assert.False(t, g.IsValid(), "GeoDatabase should be invalid when both paths are empty")

	// GetCity should return error
	ip := netip.MustParseAddr("1.1.1.1")
	_, err := g.GetCity(ip)
	assert.Error(t, err)
	assert.Equal(t, ErrNotValidConfig, err)
}

func TestInit_MissingFiles(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g := &GeoDatabase{
		ASNPath:  "/nonexistent/path/to/ASN.mmdb",
		CityPath: "/nonexistent/path/to/City.mmdb",
	}

	g.Init(ctx)

	// Should be invalid when files don't exist
	assert.False(t, g.IsValid(), "GeoDatabase should be invalid when files don't exist")

	// GetCity should return error
	ip := netip.MustParseAddr("1.1.1.1")
	_, err := g.GetCity(ip)
	assert.Error(t, err)
	assert.Equal(t, ErrNotValidConfig, err)
}

func TestInit_OneValidPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Test with only ASN path
	g := &GeoDatabase{
		ASNPath:  filepath.Join("test_data", "GeoLite2-ASN.mmdb"),
		CityPath: "",
	}

	g.Init(ctx)
	assert.True(t, g.IsValid(), "GeoDatabase should be valid with only ASN path")

	ip := netip.MustParseAddr("1.0.0.1")
	asn, err := g.GetASN(ip)
	require.NoError(t, err)
	assert.Equal(t, uint(15169), asn.AutonomousSystemNumber)

	// City should return empty record, not error
	city, err := g.GetCity(ip)
	require.NoError(t, err)
	assert.NotNil(t, city)
}

func TestInit_InvalidPathIsDirectory(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use test_data directory as an invalid path (it's a directory, not a file)
	g := &GeoDatabase{
		ASNPath:  "test_data",
		CityPath: filepath.Join("test_data", "GeoLite2-City.mmdb"),
	}

	g.Init(ctx)

	// Should be invalid when path is a directory
	assert.False(t, g.IsValid(), "GeoDatabase should be invalid when path is a directory")
}

func TestInit_WatchFilesGoroutine(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g := &GeoDatabase{
		ASNPath:  filepath.Join("test_data", "GeoLite2-ASN.mmdb"),
		CityPath: filepath.Join("test_data", "GeoLite2-City.mmdb"),
	}

	g.Init(ctx)
	assert.True(t, g.IsValid(), "GeoDatabase should be valid after successful Init")

	// Give WatchFiles goroutine a moment to initialize
	time.Sleep(100 * time.Millisecond)

	// Verify lastModTime map is initialized
	g.RLock()
	assert.NotNil(t, g.lastModTime, "lastModTime map should be initialized")
	g.RUnlock()

	// Cancel context to stop WatchFiles goroutine
	cancel()

	// Give it a moment to clean up
	time.Sleep(100 * time.Millisecond)

	// Database should still be valid after context cancellation
	assert.True(t, g.IsValid(), "GeoDatabase should remain valid after context cancellation")
}

func TestInit_EmptyFile(t *testing.T) {
	// Create a temporary empty file
	tmpFile, err := os.CreateTemp("", "empty-*.mmdb")
	require.NoError(t, err)
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	tmpFile.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g := &GeoDatabase{
		ASNPath:  tmpPath,
		CityPath: "",
	}

	g.Init(ctx)

	// Should be invalid when file is empty
	assert.False(t, g.IsValid(), "GeoDatabase should be invalid when file is empty")
}
