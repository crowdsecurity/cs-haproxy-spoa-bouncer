package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
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
	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/crowdsec-spoa/internal/api"
	"github.com/crowdsecurity/crowdsec-spoa/internal/worker"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/cfg"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/dataset"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
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
	// Parent flags
	configPath := flag.String("c", "", "path to crowdsec-spoa-bouncer.yaml")
	verbose := flag.Bool("v", false, "set verbose mode")
	bouncerVersion := flag.Bool("V", false, "display version and exit (deprecated)")
	flag.BoolVar(bouncerVersion, "version", *bouncerVersion, "display version and exit")
	testConfig := flag.Bool("t", false, "test config and exit")
	showConfig := flag.Bool("T", false, "show full config (.yaml + .yaml.local) and exit")

	// Worker flags
	workerConfigString := flag.String("config", "", "whole worker configuration as json")
	workerMode := flag.Bool("worker", false, "run as worker")

	flag.Parse()

	if !*workerMode && (*workerConfigString != "") {
		return fmt.Errorf("parent process cannot have worker config")
	}

	if *workerMode {
		var workerConfig *worker.Worker = &worker.Worker{}
		err := json.Unmarshal([]byte(*workerConfigString), workerConfig)
		if err != nil {
			return fmt.Errorf("unable to unmarshal worker config: %w", err)
		}
		if workerConfig.ListenAddr == "" && workerConfig.ListenSocket == "" {
			return fmt.Errorf("worker process must have one listener address: %+v", *workerConfigString)
		}
		return WorkerExecute(workerConfig)
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
	log.Debugf("Configuration: %+v", config.Workers[0])
	log.Debugf("Configuration: %+v", *config.AppSec)
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

	if config.PrometheusConfig.Enabled {

		prometheus.MustRegister(csbouncer.TotalLAPICalls, csbouncer.TotalLAPIError)

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

	ctx, cancel := context.WithCancel(context.Background())
	workerManager := worker.NewManager(ctx, &cancel, workerServer, config.WorkerUid, config.WorkerGid)

	g.Go(func() error {
		return workerManager.Run()
	})

	apiServer := api.NewApi(ctx, workerManager, HostManager, dataSet, &config.Geo, socketConnChan)

	for _, worker := range config.Workers {
		log.Debugf("Adding worker %v", worker)
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

func WorkerExecute(workerConfig *worker.Worker) error {

	g, ctx := errgroup.WithContext(context.Background())

	g.Go(func() error {
		return HandleSignals(ctx)
	})

	spoad, err := spoa.New(workerConfig)

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
		return fmt.Errorf("failed to shutdown server: %s", err)
	}

	return nil
}
