package geo

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
	log "github.com/sirupsen/logrus"
)

var (
	NOT_VALID_CONFIG = fmt.Errorf("geo database is not initialized")
)

type GeoDatabase struct {
	ASNPath      string               `yaml:"asn_database_path"`  // Path to the ASN database
	CityPath     string               `yaml:"city_database_path"` // Path to the city database
	asnReader    *geoip2.Reader       `yaml:"-"`                  // Reader for the ASN database
	cityReader   *geoip2.Reader       `yaml:"-"`                  // Reader for the city database
	lastModTime  map[string]time.Time `yaml:"-"`                  // Last modification time of the databases
	sync.RWMutex `yaml:"-"`
}

func (g *GeoDatabase) Init(ctx context.Context) {

	if !g.IsValid() {
		log.Warnf("geo database paths not configured, disabling module")
		return
	}

	if err := g.open(); err != nil {
		log.Errorf("failed to open databases: %s", err)
	}

	go g.WatchFiles(ctx)
}

func (g *GeoDatabase) reload() error {
	g.close()
	return g.open()
}

func (g *GeoDatabase) open() error {
	g.Lock()
	defer g.Unlock()
	var err error
	if g.asnReader == nil && g.ASNPath != "" {
		g.asnReader, err = geoip2.Open(g.ASNPath)
		if err != nil {
			return err
		}
	}

	if g.cityReader == nil && g.CityPath != "" {
		g.cityReader, err = geoip2.Open(g.CityPath)
		if err != nil {
			return err
		}
	}

	return nil
}

func (g *GeoDatabase) close() {
	g.Lock()
	defer g.Unlock()
	if g.asnReader != nil {
		g.asnReader.Close()
		g.asnReader = nil
	}

	if g.cityReader != nil {
		g.cityReader.Close()
		g.cityReader = nil
	}
}

func (g *GeoDatabase) IsValid() bool {
	return g.ASNPath != "" && g.CityPath != ""
}

func (g *GeoDatabase) GetASN(ip *net.IP) (*geoip2.ASN, error) {

	if !g.IsValid() {
		return nil, NOT_VALID_CONFIG
	}

	g.RLock()
	defer g.RUnlock()
	record := &geoip2.ASN{}

	record, err := g.asnReader.ASN(*ip)
	if err != nil {
		return record, err
	}

	return record, nil
}

func (g *GeoDatabase) GetCity(ip *net.IP) (*geoip2.City, error) {

	if !g.IsValid() {
		return nil, NOT_VALID_CONFIG
	}

	g.RLock()
	defer g.RUnlock()
	record := &geoip2.City{}

	record, err := g.cityReader.City(*ip)
	if err != nil {
		return record, err
	}

	return record, nil
}

// Just a simple helper function to get the ISO code from the record in the same order as CrowdSec
func GetIsoCodeFromRecord(record *geoip2.City) string {
	if record.Country.IsoCode != "" {
		return record.Country.IsoCode
	}
	if record.RegisteredCountry.IsoCode != "" {
		return record.RegisteredCountry.IsoCode
	}
	if record.RepresentedCountry.IsoCode != "" {
		return record.RepresentedCountry.IsoCode
	}
	return ""
}

// WatchFiles watches the ASN and city databases for changes and reloads them if necessary
// Primarily written to stop the errors that were present in CrowdSec codebase
// !TODO we should maybe extend this to use fsnotify if the user filesystem supports it
func (g *GeoDatabase) WatchFiles(ctx context.Context) {
	// If both are nil then there is no need to watch
	if g.asnReader == nil && g.cityReader == nil {
		return
	}

	ticker := time.NewTicker(1 * time.Minute)
	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			shouldUpdate := false
			if asnLastModTime, ok := g.lastModTime[g.ASNPath]; ok {
				info, err := os.Stat(g.ASNPath)
				if err != nil {
					log.Printf("failed to stat ASN database: %s", err)
					continue
				}
				if info.ModTime().After(asnLastModTime) {
					log.Printf("ASN database has been updated, reloading")
					shouldUpdate = true
					g.lastModTime[g.ASNPath] = info.ModTime()
				}
			} else {
				info, err := os.Stat(g.ASNPath)
				if err != nil {
					log.Printf("failed to stat ASN database: %s", err)
					continue
				}
				g.lastModTime[g.ASNPath] = info.ModTime()
			}
			if cityLastModTime, ok := g.lastModTime[g.CityPath]; ok {
				info, err := os.Stat(g.CityPath)
				if err != nil {
					log.Printf("failed to stat city database: %s", err)
					continue
				}
				if info.ModTime().After(cityLastModTime) {
					log.Printf("City database has been updated, reloading")
					shouldUpdate = true
					g.lastModTime[g.CityPath] = info.ModTime()
				}
			} else {
				info, err := os.Stat(g.CityPath)
				if err != nil {
					log.Printf("failed to stat city database: %s", err)
					continue
				}
				g.lastModTime[g.CityPath] = info.ModTime()
			}
			if shouldUpdate {
				if err := g.reload(); err != nil {
					log.Printf("failed to reload databases: %s", err)
				}
			}
		}
	}
}
