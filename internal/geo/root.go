package geo

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/oschwald/geoip2-golang/v2"
	log "github.com/sirupsen/logrus"
)

var (
	ErrNotValidConfig = fmt.Errorf("geo database is not initialized")
)

// isPermissionError checks if an error is a permission error, unwrapping if necessary
func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	if os.IsPermission(err) {
		return true
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return os.IsPermission(pathErr.Err)
	}
	return false
}

type GeoDatabase struct {
	ASNPath      string               `yaml:"asn"`  // Path to the ASN database (new nested config)
	CityPath     string               `yaml:"city"` // Path to the city database (new nested config)
	UseStat      bool                 `yaml:"stat"` // Use stat polling instead of fsnotify (for SMB/network shares)
	asnReader    *geoip2.Reader       `yaml:"-"`    // Reader for the ASN database
	cityReader   *geoip2.Reader       `yaml:"-"`    // Reader for the city database
	lastModTime  map[string]time.Time `yaml:"-"`    // Last modification time of the databases
	loadFailed   bool                 `yaml:"-"`    // Whether the databases failed to load
	watcher      *fsnotify.Watcher    `yaml:"-"`    // fsnotify watcher
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

// Close cleans up resources (watchers, readers, etc.)
func (g *GeoDatabase) Close() {
	g.Lock()
	defer g.Unlock()

	if g.watcher != nil {
		g.watcher.Close()
		g.watcher = nil
	}

	if g.asnReader != nil {
		g.asnReader.Close()
		g.asnReader = nil
	}

	if g.cityReader != nil {
		g.cityReader.Close()
		g.cityReader = nil
	}
}

// reload attempts to reload the databases. If reload fails due to permission errors,
// it keeps the old readers to prevent hard failure and continues serving with existing data.
// Returns an error only for non-permission errors that should be retried.
func (g *GeoDatabase) reload() error {
	// Try to open new readers first
	var newASNReader *geoip2.Reader
	var newCityReader *geoip2.Reader
	var asnErr, cityErr error

	// Check if we have existing readers to fall back to
	g.RLock()
	hasExistingASN := g.asnReader != nil
	hasExistingCity := g.cityReader != nil
	g.RUnlock()

	// Try to open ASN database
	if g.ASNPath != "" {
		newASNReader, asnErr = geoip2.Open(g.ASNPath)
		if asnErr != nil && isPermissionError(asnErr) && hasExistingASN {
			// Permission error but we have existing reader - keep using it
			log.Warnf("permission denied opening ASN database (keeping existing data): %s", asnErr)
			newASNReader = nil // Don't update, keep old reader
			asnErr = nil       // Clear error so we continue
		}
	}

	// Try to open City database
	if g.CityPath != "" {
		newCityReader, cityErr = geoip2.Open(g.CityPath)
		if cityErr != nil && isPermissionError(cityErr) && hasExistingCity {
			// Permission error but we have existing reader - keep using it
			log.Warnf("permission denied opening City database (keeping existing data): %s", cityErr)
			newCityReader = nil // Don't update, keep old reader
			cityErr = nil       // Clear error so we continue
		}
	}

	// If we have non-permission errors, return them
	if asnErr != nil {
		// Clean up any successfully opened readers
		if newCityReader != nil {
			newCityReader.Close()
		}
		return fmt.Errorf("failed to open ASN database: %w", asnErr)
	}
	if cityErr != nil {
		// Clean up any successfully opened readers
		if newASNReader != nil {
			newASNReader.Close()
		}
		return fmt.Errorf("failed to open City database: %w", cityErr)
	}

	// Update readers atomically - only swap the ones we successfully opened
	g.Lock()
	var oldASNReader, oldCityReader *geoip2.Reader

	if newASNReader != nil {
		oldASNReader = g.asnReader
		g.asnReader = newASNReader
	}
	if newCityReader != nil {
		oldCityReader = g.cityReader
		g.cityReader = newCityReader
	}
	g.Unlock()

	// Close old readers after swap (only the ones we replaced)
	if oldASNReader != nil {
		oldASNReader.Close()
	}
	if oldCityReader != nil {
		oldCityReader.Close()
	}

	return nil
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

// WatchFiles watches the ASN and city databases for changes and reloads them if necessary.
// Uses fsnotify by default, but falls back to stat polling if UseStat is true or fsnotify fails.
func (g *GeoDatabase) WatchFiles(ctx context.Context) {
	if g.UseStat {
		g.watchFilesWithStat(ctx)
		return
	}

	// Try to use fsnotify
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Warnf("failed to create fsnotify watcher (falling back to stat polling): %s", err)
		g.watchFilesWithStat(ctx)
		return
	}

	g.Lock()
	g.watcher = watcher
	g.Unlock()

	// Watch directories containing the database files
	watchedDirs := make(map[string]bool)
	if g.ASNPath != "" {
		dir := filepath.Dir(g.ASNPath)
		if !watchedDirs[dir] {
			if err := watcher.Add(dir); err != nil {
				log.Warnf("failed to watch ASN database directory %s (falling back to stat polling): %s", dir, err)
				watcher.Close()
				g.watchFilesWithStat(ctx)
				return
			}
			watchedDirs[dir] = true
		}
	}

	if g.CityPath != "" {
		dir := filepath.Dir(g.CityPath)
		if !watchedDirs[dir] {
			if err := watcher.Add(dir); err != nil {
				log.Warnf("failed to watch City database directory %s (falling back to stat polling): %s", dir, err)
				watcher.Close()
				g.watchFilesWithStat(ctx)
				return
			}
			watchedDirs[dir] = true
		}
	}

	log.Info("using fsnotify for geo database file monitoring")

	// Targets we care about (ASN and City)
	type target struct {
		path  string
		label string
	}
	targets := []target{
		{path: g.ASNPath, label: "ASN"},
		{path: g.CityPath, label: "City"},
	}

	// Debounce timer to coalesce rapid events (e.g., Write + Chmod in quick succession)
	const debounceDelay = 500 * time.Millisecond
	var debounceTimer *time.Timer
	var pendingReload bool

	// Helper to execute reload with mtime updates
	doReload := func() {
		pendingReload = false
		if err := g.reload(); err != nil {
			log.Errorf("failed to reload databases (keeping existing data): %s", err)
		} else {
			// Update mtimes for all known targets after successful reload
			for _, t := range targets {
				if t.path == "" {
					continue
				}
				if info, err := os.Stat(t.path); err == nil {
					g.updateModTime(t.path, info.ModTime())
				}
			}
			log.Info("successfully reloaded geo databases")
		}
	}

	// Watch for file changes
	for {
		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			watcher.Close()
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove|fsnotify.Chmod) == 0 {
				continue
			}

			shouldReload := false

			for _, t := range targets {
				if t.path == "" {
					continue
				}

				// Direct match on path or basename in same directory (covers overwrite in place)
				// Also handle Chmod events (permission changes) - try to reload if permissions were fixed
				eventDir := filepath.Dir(event.Name)
				targetDir := filepath.Dir(t.path)
				if event.Name == t.path || (filepath.Base(event.Name) == filepath.Base(t.path) && eventDir == targetDir) {
					if event.Op&fsnotify.Chmod != 0 {
						log.Infof("%s database file permissions changed (event: %s, op: %s), attempting reload", t.label, event.Name, event.Op)
					} else {
						log.Infof("%s database file changed (event: %s, op: %s), reloading", t.label, event.Name, event.Op)
					}
					shouldReload = true
					break
				}

				// Atomic rename into place: event.Name is the source path in the same directory
				if event.Op&fsnotify.Rename != 0 && eventDir == targetDir {
					if info, err := os.Stat(t.path); err == nil {
						g.RLock()
						lastModTime, exists := g.lastModTime[t.path]
						g.RUnlock()

						if !exists || info.ModTime().After(lastModTime) {
							log.Infof("%s database file changed via rename (event: %s -> %s, op: %s), reloading",
								t.label, event.Name, t.path, event.Op)
							shouldReload = true
							break
						}
					}
				}
			}

			if shouldReload && !pendingReload {
				pendingReload = true
				// Debounce: wait briefly to coalesce rapid events
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.AfterFunc(debounceDelay, doReload)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Warnf("fsnotify error (falling back to stat polling): %s", err)
			watcher.Close()
			g.watchFilesWithStat(ctx)
			return
		}
	}
}

// watchFilesWithStat uses stat polling to check for file changes (for SMB/network shares)
func (g *GeoDatabase) watchFilesWithStat(ctx context.Context) {
	log.Info("using stat polling for geo database file monitoring")
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check both databases first, then reload once if any changed
			var asnModTime, cityModTime time.Time
			shouldReload := false

			if g.ASNPath != "" {
				if changed, modTime := g.checkModTime(g.ASNPath, "ASN"); changed {
					shouldReload = true
					asnModTime = modTime
				}
			}

			if g.CityPath != "" {
				if changed, modTime := g.checkModTime(g.CityPath, "City"); changed {
					shouldReload = true
					cityModTime = modTime
				}
			}

			if shouldReload {
				if err := g.reload(); err != nil {
					log.Errorf("failed to reload databases (keeping existing data): %s", err)
					// Don't update mtime on failure - allows retry on next tick
				} else {
					log.Info("successfully reloaded geo databases")
					// Only update mtimes after successful reload
					g.updateModTime(g.ASNPath, asnModTime)
					g.updateModTime(g.CityPath, cityModTime)
				}
			}
		}
	}
}

// checkModTime checks if a database file has been modified without updating the lastModTime.
// Returns (shouldReload, newModTime). The mtime should only be updated after successful reload.
// This allows retry on failure since the mtime won't be updated until reload succeeds.
func (g *GeoDatabase) checkModTime(path, dbType string) (bool, time.Time) {
	info, err := os.Stat(path)
	if err != nil {
		log.Warnf("failed to stat %s database: %s", dbType, err)
		return false, time.Time{}
	}

	newModTime := info.ModTime()

	g.RLock()
	lastModTime, exists := g.lastModTime[path]
	g.RUnlock()

	if !exists {
		// First time checking this file - initialize mtime but don't trigger reload
		// (file was just loaded during Init, no need to reload immediately)
		g.Lock()
		g.lastModTime[path] = newModTime
		g.Unlock()
		return false, time.Time{}
	}

	if newModTime.After(lastModTime) {
		log.Infof("%s database has been updated, reloading", dbType)
		// Return newModTime but DON'T update the map yet - wait for successful reload
		return true, newModTime
	}

	return false, time.Time{}
}

// updateModTime updates the lastModTime for a path (called after successful reload)
func (g *GeoDatabase) updateModTime(path string, modTime time.Time) {
	if modTime.IsZero() {
		return
	}
	g.Lock()
	g.lastModTime[path] = modTime
	g.Unlock()
}
