package geo

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang/v2"
	log "github.com/sirupsen/logrus"
)

var (
	ErrNotValidConfig = fmt.Errorf("geo database is not initialized")
)

type GeoDatabase struct {
	ASNPath      string               `yaml:"asn_database_path"`  // Path to the ASN database
	CityPath     string               `yaml:"city_database_path"` // Path to the city database
	asnReader    *geoip2.Reader       `yaml:"-"`                  // Reader for the ASN database
	cityReader   *geoip2.Reader       `yaml:"-"`                  // Reader for the city database
	lastModTime  map[string]time.Time `yaml:"-"`                  // Last modification time of the databases
	loadFailed   bool                 `yaml:"-"`                  // Whether the databases failed to load
	sync.RWMutex `yaml:"-"`
}

func (g *GeoDatabase) Init(ctx context.Context) {

	if g.ASNPath == "" && g.CityPath == "" {
		log.Warnf("geo database paths not configured, disabling module")
		g.loadFailed = true
		return
	}

	// Validate paths exist before attempting to load
	if err := g.validatePaths(); err != nil {
		log.Errorf("geo database path validation failed: %s", err)
		g.loadFailed = true
		return
	}

	if err := g.open(); err != nil {
		log.Errorf("failed to open databases: %s", err)
		g.loadFailed = true
		return
	}

	g.lastModTime = make(map[string]time.Time)

	go g.WatchFiles(ctx)
}

func (g *GeoDatabase) reload() error {
	g.close()
	return g.open()
}

// validatePaths checks if the configured database paths exist and are readable
func (g *GeoDatabase) validatePaths() error {
	if g.ASNPath != "" {
		if err := g.validatePath(g.ASNPath, "ASN"); err != nil {
			return err
		}
	}

	if g.CityPath != "" {
		if err := g.validatePath(g.CityPath, "City"); err != nil {
			return err
		}
	}

	return nil
}

// validatePath checks if a single database path exists and is readable
func (g *GeoDatabase) validatePath(path, dbType string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s database file does not exist: %s", dbType, path)
		}
		return fmt.Errorf("failed to stat %s database file %s: %w", dbType, path, err)
	}

	if info.IsDir() {
		return fmt.Errorf("%s database path is a directory, not a file: %s", dbType, path)
	}

	if info.Size() == 0 {
		return fmt.Errorf("%s database file is empty: %s", dbType, path)
	}

	return nil
}

func (g *GeoDatabase) open() error {
	g.Lock()
	defer g.Unlock()

	var err error
	if g.asnReader == nil && g.ASNPath != "" {
		g.asnReader, err = geoip2.Open(g.ASNPath)
		if err != nil {
			return fmt.Errorf("failed to open ASN database: %w", err)
		}
	}

	if g.cityReader == nil && g.CityPath != "" {
		g.cityReader, err = geoip2.Open(g.CityPath)
		if err != nil {
			// Clean up ASN reader if it was opened successfully
			if g.asnReader != nil {
				g.asnReader.Close()
				g.asnReader = nil
			}
			return fmt.Errorf("failed to open City database: %w", err)
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
	return !g.loadFailed
}

func (g *GeoDatabase) GetASN(ip netip.Addr) (*geoip2.ASN, error) {
	if !g.IsValid() {
		return nil, ErrNotValidConfig
	}

	g.RLock()
	defer g.RUnlock()

	if g.asnReader == nil {
		return &geoip2.ASN{}, nil
	}

	record, err := g.asnReader.ASN(ip)
	if err != nil {
		return record, err
	}

	return record, nil
}

func (g *GeoDatabase) GetCity(ip netip.Addr) (*geoip2.City, error) {
	if !g.IsValid() {
		return nil, ErrNotValidConfig
	}

	g.RLock()
	defer g.RUnlock()

	if g.cityReader == nil {
		return &geoip2.City{}, nil
	}

	record, err := g.cityReader.City(ip)
	if err != nil {
		return record, err
	}

	return record, nil
}

// Just a simple helper function to get the ISO code from the record in the same order as CrowdSec
// Updated for v2: field names changed from IsoCode to ISOCode
func GetIsoCodeFromRecord(record *geoip2.City) string {
	if record == nil {
		return ""
	}

	if record.Country.ISOCode != "" {
		return record.Country.ISOCode
	}
	if record.RegisteredCountry.ISOCode != "" {
		return record.RegisteredCountry.ISOCode
	}
	if record.RepresentedCountry.ISOCode != "" {
		return record.RepresentedCountry.ISOCode
	}
	return ""
}

// WatchFiles watches the ASN and city databases for changes and reloads them if necessary
// Primarily written to stop the errors that were present in CrowdSec codebase
// !TODO we should maybe extend this to use fsnotify if the user filesystem supports it
func (g *GeoDatabase) WatchFiles(ctx context.Context) {

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			shouldUpdate := false

			// Check ASN database
			if g.ASNPath != "" {
				if updated := g.checkAndUpdateModTime(g.ASNPath, "ASN"); updated {
					shouldUpdate = true
				}
			}

			// Check City database
			if g.CityPath != "" {
				if updated := g.checkAndUpdateModTime(g.CityPath, "City"); updated {
					shouldUpdate = true
				}
			}

			if shouldUpdate {
				if err := g.reload(); err != nil {
					log.Warnf("failed to reload databases: %s", err)
				}
			}
		}
	}
}

// checkAndUpdateModTime checks if a database file has been modified and updates the lastModTime
// Returns true if the file was updated (needs reload), false otherwise
func (g *GeoDatabase) checkAndUpdateModTime(path, dbType string) bool {
	info, err := os.Stat(path)
	if err != nil {
		log.Warnf("failed to stat %s database: %s", dbType, err)
		return false
	}

	g.RLock()
	lastModTime, exists := g.lastModTime[path]
	g.RUnlock()

	if !exists {
		// First time checking this file, just record the mod time
		g.Lock()
		g.lastModTime[path] = info.ModTime()
		g.Unlock()
		return false
	}

	if info.ModTime().After(lastModTime) {
		log.Infof("%s database has been updated, reloading", dbType)
		g.Lock()
		g.lastModTime[path] = info.ModTime()
		g.Unlock()
		return true
	}

	return false
}
