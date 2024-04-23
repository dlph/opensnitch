package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/evilsocket/opensnitch/service"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "",
	Short:   "run daemon",
	Long:    ``,
	RunE:    runRootE,
	Version: "0.0.1-beta",
}

func runRootE(cmd *cobra.Command, args []string) error {
	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	setupSignals(cancelFn)

	fs := afero.NewOsFs()

	logger, err := newLogger(fs)
	if err != nil {
		return err
	}

	cfg, err := newViperConfig(cmd, fs, logger)
	if err != nil {
		return err
	}

	slog.Debug("creating new service daemon")
	svc, err := service.New(cfg)
	if err != nil {
		return err
	}

	// run and block
	slog.Debug("service run")
	if err := svc.Run(ctx); err != nil {
		return err
	}

	return svc.Stop(ctx)
}

func setupSignals(cancelFn context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		select {
		case sig := <-sigChan:
			slog.Info("received quit signal", "sig", sig.String())
			cancelFn()

			time.AfterFunc(10*time.Second, func() {
				slog.Error("[REVIEW] exiting after timout")
				os.Exit(1)
			})
		}
	}()
}
