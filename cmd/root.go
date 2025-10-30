package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/crowdsec-spoa/internal/admin"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/cfg"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/dataset"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/metrics"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/spoa"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/crowdsecurity/go-cs-lib/csdaemon"
	"github.com/crowdsecurity/go-cs-lib/csstring"
	"github.com/crowdsecurity/go-cs-lib/version"
)

const name = "crowdsec-spoa-bouncer"

func HandleSignals(ctx context.Context) error {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, os.Interrupt)

	select {
	case s := <-signalChan:
		switch s {
		case syscall.SIGTERM:
			return errors.New("received SIGTERM")
		case os.Interrupt: // cross-platform SIGINT
			return errors.New("received interrupt")
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func Execute() error {
	// Parent pflags
	configPath := pflag.StringP("config", "c", "/etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml", "path to crowdsec-spoa-bouncer.yaml")
	verbose := pflag.BoolP("verbose", "v", false, "set verbose mode")
	bouncerVersion := pflag.BoolP("V", "V", false, "display version and exit (deprecated)")
	pflag.BoolVar(bouncerVersion, "version", *bouncerVersion, "display version and exit")
	testConfig := pflag.BoolP("test", "t", false, "test config and exit")
	showConfig := pflag.BoolP("show-config", "T", false, "show full config (.yaml + .yaml.local) and exit")

	pflag.Parse()

	// Handle version flags
	if *bouncerVersion {
		fmt.Fprint(os.Stdout, version.FullString())
		return nil
	}

	if configPath == nil || *configPath == "" {
		return errors.New("configuration file is required")
	}

	configMerged, err := cfg.MergedConfig(*configPath)
	if err != nil {
		return fmt.Errorf("unable to read config file: %w", err)
	}

	if *showConfig {
		fmt.Println(string(configMerged))
		return nil
	}

	configExpanded := csstring.StrictExpand(string(configMerged), os.LookupEnv)

	config, err := cfg.NewConfig(strings.NewReader(configExpanded))
	if err != nil {
		return fmt.Errorf("unable to load configuration: %w", err)
	}

	if *verbose && log.GetLevel() < log.DebugLevel {
		log.SetLevel(log.DebugLevel)
	}

	log.Infof("Starting %s %s", name, version.String())

	bouncer := &csbouncer.StreamBouncer{}

	err = bouncer.ConfigReader(strings.NewReader(configExpanded))
	if err != nil {
		return err
	}

	bouncer.UserAgent = fmt.Sprintf("%s/%s", name, version.String())
	if err := bouncer.Init(); err != nil {
		return fmt.Errorf("unable to configure bouncer: %w", err)
	}

	g, ctx := errgroup.WithContext(context.Background())

	config.Geo.Init(ctx)

	if *testConfig {
		log.Info("config is valid")
		return nil
	}

	if bouncer.InsecureSkipVerify != nil {
		log.Debugf("InsecureSkipVerify is set to %t", *bouncer.InsecureSkipVerify)
	}

	g.Go(func() error {
		return HandleSignals(ctx)
	})

	g.Go(func() error {
		err := bouncer.Run(ctx)
		return fmt.Errorf("bouncer run halted: %w", err)
	})

	metricsProvider, err := csbouncer.NewMetricsProvider(bouncer.APIClient, name, metricsUpdater, log.StandardLogger())

	if err != nil {
		return fmt.Errorf("failed to create metrics provider: %w", err)
	}

	g.Go(func() error {
		return metricsProvider.Run(ctx)
	})

	prometheus.MustRegister(csbouncer.TotalLAPICalls, csbouncer.TotalLAPIError, metrics.TotalActiveDecisions, metrics.TotalBlockedRequests, metrics.TotalProcessedRequests)

	if config.PrometheusConfig.Enabled {
		go func() {
			http.Handle("/metrics", promhttp.Handler())

			listenOn := net.JoinHostPort(
				config.PrometheusConfig.ListenAddress,
				config.PrometheusConfig.ListenPort,
			)
			log.Infof("Serving metrics at %s", listenOn+"/metrics")
			log.Error(http.ListenAndServe(listenOn, nil))
		}()
	}

	dataSet := dataset.New()

	g.Go(func() error {
		log.Infof("Processing new and deleted decisions . . .")

		for {
			select {
			case <-ctx.Done():
				return nil
			case decisions := <-bouncer.Stream:
				if decisions == nil {
					continue
				}
				if len(decisions.New) > 0 {
					log.Debugf("Processing %d new decisions", len(decisions.New))
					dataSet.Add(decisions.New)
				}
				if len(decisions.Deleted) > 0 {
					log.Debugf("Processing %d deleted decisions", len(decisions.Deleted))
					dataSet.Remove(decisions.Deleted)
				}
			}
		}
	})

	// Create a base logger for the host manager
	hostManagerLogger := log.WithField("component", "host_manager")
	HostManager := host.NewManager(hostManagerLogger)

	g.Go(func() error {
		HostManager.Run(ctx)
		return nil
	})

	for _, h := range config.Hosts {
		HostManager.Chan <- host.HostOp{
			Host: h,
			Op:   host.OpAdd,
		}
	}

	if config.HostsDir != "" {
		if err := HostManager.LoadFromDirectory(config.HostsDir); err != nil {
			return fmt.Errorf("failed to load hosts from directory: %w", err)
		}
	}

	// Create single SPOA listener - ultra-simplified architecture
	spoaLogger := log.WithField("component", "spoa")

	// Create single SPOA directly with minimal configuration
	spoaConfig := &spoa.SpoaConfig{
		TcpAddr:     config.ListenTCP,
		UnixAddr:    config.ListenUnix,
		Dataset:     dataSet,
		HostManager: HostManager,
		GeoDatabase: &config.Geo,
		Logger:      spoaLogger,
	}

	singleSpoa, err := spoa.New(spoaConfig)
	if err != nil {
		return fmt.Errorf("failed to create SPOA listener: %w", err)
	}

	// Launch single SPOA server directly
	g.Go(func() error {
		if err := singleSpoa.Serve(ctx); err != nil {
			return fmt.Errorf("SPOA server failed: %w", err)
		}
		return nil
	})

	// Admin server will inherit root logger and log level via its fallback

	// Setup admin socket (systemd activation or config-based)
	adminServer, err := admin.NewServer(ctx, admin.Config{
		SocketPath:  config.AdminSocket,
		HostManager: HostManager,
		Dataset:     dataSet,
		GeoDatabase: &config.Geo,
	})
	if err != nil {
		return fmt.Errorf("failed to create admin server: %w", err)
	}

	// Start admin server if it has listeners
	if adminServer.HasListeners() {
		g.Go(func() error {
			return adminServer.Run()
		})
	}

	_ = csdaemon.Notify(csdaemon.Ready, log.StandardLogger())

	err = g.Wait()

	// Determine if this was an expected shutdown signal
	isExpectedShutdown := false
	if err != nil {
		switch err.Error() {
		case "received SIGTERM":
			log.Info("Received SIGTERM, shutting down")
			isExpectedShutdown = true
		case "received interrupt":
			log.Info("Received interrupt, shutting down")
			isExpectedShutdown = true
		}
	}

	// Shutdown SPOA server gracefully after all goroutines finish
	log.Info("Shutting down SPOA listener")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if shutdownErr := singleSpoa.Shutdown(shutdownCtx); shutdownErr != nil {
		log.Errorf("Failed to shutdown SPOA: %v", shutdownErr)
	}

	// Return error only if it was unexpected
	if err != nil && !isExpectedShutdown {
		return err
	}

	return nil
}
