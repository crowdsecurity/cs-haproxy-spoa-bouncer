package geo

import (
	"context"
	"net"
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

	ip := net.ParseIP("2.125.160.216")
	city, err := g.GetCity(&ip)
	if err != nil {
		t.Fatalf("GetCity returned error: %v", err)
	}

	assert.Equal(t, city.City.Names["en"], "Boxford", "Expected city name 'Boxford', got '%s'", city.City.Names["en"])
	assert.Equal(t, city.Continent.Names["en"], "Europe", "Expected continent name 'Europe', got '%s'", city.City.Names["en"])

	ip = net.ParseIP("1.0.0.1")
	asn, err := g.GetASN(&ip)
	if err != nil {
		t.Fatalf("GetCity returned error: %v", err)
	}
	assert.Equal(t, uint(15169), asn.AutonomousSystemNumber, "Expected ASN 15169, got %d", asn.AutonomousSystemNumber)
	t.Logf("City: %+v", asn)

	ip = net.ParseIP("1.1.1.1")
	city, err = g.GetCity(&ip)
	if err != nil {
		t.Fatalf("GetCity returned error: %v", err)
	}
	assert.Equal(t, city.City.Names["en"], "", "Expected city name '', got '%s'", city.City.Names["en"])
	assert.Equal(t, city.Continent.Names["en"], "", "Expected continent name '', got '%s'", city.City.Names["en"])

}
