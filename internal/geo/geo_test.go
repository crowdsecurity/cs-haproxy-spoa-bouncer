package geo

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetCityAndASN(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g := &GeoDatabase{
		ASNPath:  filepath.Join("test_data", "GeoLite2-ASN.mmdb"),
		CityPath: filepath.Join("test_data", "GeoLite2-City.mmdb"),
	}

	g.Init(ctx)

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
