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

	"github.com/crowdsecurity/crowdsec-spoa/internal/api"
	"github.com/crowdsecurity/crowdsec-spoa/internal/worker"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/cfg"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/dataset"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/metrics"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/server"
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
	configPath := pflag.String("c", "", "path to crowdsec-spoa-bouncer.yaml")
	verbose := pflag.Bool("v", false, "set verbose mode")
	bouncerVersion := pflag.Bool("V", false, "display version and exit (deprecated)")
	pflag.BoolVar(bouncerVersion, "version", *bouncerVersion, "display version and exit")
	testConfig := pflag.Bool("t", false, "test config and exit")
	showConfig := pflag.Bool("T", false, "show full config (.yaml + .yaml.local) and exit")

	// Worker pflags
	tcpAddr := pflag.String("tcp", "", "tcp listener address")
	unixAddr := pflag.String("unix", "", "unix listener address")
	workerMode := pflag.Bool("worker", false, "run as worker")

	pflag.Parse()

	if !*workerMode && (*tcpAddr != "" || *unixAddr != "") {
		return fmt.Errorf("parent process cannot have listener address")
	}

	if *workerMode {
		if *tcpAddr == "" && *unixAddr == "" {
			return fmt.Errorf("worker process must have one listener address")
		}
		return WorkerExecute(*tcpAddr, *unixAddr)
	}

	if *bouncerVersion {
		fmt.Print(version.FullString())
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
		bouncer.Run(ctx)
		return errors.New("bouncer stream halted")
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

	HostManager := host.NewManager(ctx)

	g.Go(func() error {
		HostManager.Run()
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

	socketConnChan := make(chan server.SocketConn)

	workerServer, err := server.NewWorkerSocket(socketConnChan, config.WorkerSocketDir)

	if err != nil {
		return fmt.Errorf("failed to create worker server: %w", err)
	}

	if config.AdminSocket != "" {
		adminServer, err := server.NewAdminSocket(socketConnChan)

		if err != nil {
			return fmt.Errorf("failed to create admin server: %w", err)
		}

		adminServer.NewAdminListener(config.AdminSocket)
		defer adminServer.Close()
	}

	workerManager := worker.NewManager(ctx, workerServer, config.WorkerUid, config.WorkerGid)

	g.Go(func() error {
		return workerManager.Run()
	})

	apiServer := api.NewApi(ctx, workerManager, HostManager, dataSet, &config.Geo, socketConnChan)

	for _, worker := range config.Workers {
		workerManager.CreateChan <- worker
	}

	g.Go(func() error {
		return apiServer.Run()
	})

	_ = csdaemon.Notify(csdaemon.Ready, log.StandardLogger())

	if err := g.Wait(); err != nil {
		switch err.Error() {
		case "received SIGTERM":
			log.Info("Received SIGTERM, shutting down")
		case "received interrupt":
			log.Info("Received interrupt, shutting down")
		default:
			return err
		}
	}

	workerServer.Close()

	return nil
}

func WorkerExecute(tcpAddr, unixAddr string) error {

	g, ctx := errgroup.WithContext(context.Background())

	g.Go(func() error {
		return HandleSignals(ctx)
	})

	spoad, err := spoa.New(tcpAddr, unixAddr)

	if err != nil {
		return fmt.Errorf("failed to create SPOA: %w", err)
	}

	g.Go(func() error {
		if err := spoad.ServeTCP(ctx); err != nil {
			return fmt.Errorf("failed to serve TCP: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		if err := spoad.ServeUnix(ctx); err != nil {
			return fmt.Errorf("failed to serve Unix: %w", err)
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		switch err.Error() {
		case "received SIGTERM":
		case "received interrupt":
		default:
			return err
		}
	}

	cancelCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := spoad.Shutdown(cancelCtx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}

	return nil
}
