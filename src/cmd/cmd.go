package cmd

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Execute() error {
	rootCmd.Flags().String("process-monitor-method", "ebpf", "How to search for processes path. Options: ftrace, audit (experimental), ebpf (experimental), proc (default)")
	rootCmd.Flags().String("ui-socket", "unix:///tmp/osui.sock", "Path the UI gRPC service listener (https://github.com/grpc/grpc/blob/master/doc/naming.md).")
	rootCmd.Flags().Int("queue-num", 0, "Netfilter queue number.")
	rootCmd.Flags().Int("workers", 16, "Number of concurrent workers.")
	rootCmd.Flags().Bool("no-live-reload", false, "Disable rules live reloading.")

	rootCmd.Flags().String("rules-path", "/etc/opensnitchd/rules", "Path to load JSON rules from.")
	rootCmd.Flags().String("config-file", "/etc/opensnitchd/default-config.json", "Path to the daemon configuration file.")
	rootCmd.Flags().String("fw-config-file", "/etc/opensnitchd/system-fw.json", "Path to the system fw configuration file.")
	//flag.StringVar(&ebpfModPath, "ebpf-modules-path", ebpfModPath, "Path to the directory with the eBPF modules.")
	rootCmd.Flags().String("log-file", "", "Write logs to this file instead of the standard output.")
	rootCmd.Flags().Bool("log-utc", true, "Write logs output with UTC timezone (enabled by default).")
	rootCmd.Flags().Bool("log-micro", false, "Write logs output with microsecond timestamp (disabled by default).")
	rootCmd.Flags().Bool("debug", false, "Enable debug level logs.")
	rootCmd.Flags().Bool("warning", false, "Enable warning level logs.")
	rootCmd.Flags().Bool("important", false, "Enable important level logs.")
	rootCmd.Flags().Bool("error", false, "Enable error level logs.")

	rootCmd.Flags().String("cpu-profile", "", "Write CPU profile to this file.")
	rootCmd.Flags().String("mem-profile", "", "Write memory profile to this file.")
	rootCmd.Flags().String("trace-file", "", "Write trace file to this file.")

	rootCmd.AddCommand(requirementsCmd)

	return rootCmd.Execute()
}

// TODO: log to file
func newLogger(_ afero.Fs) (*zap.Logger, error) {
	// zap
	highPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl >= zapcore.ErrorLevel
	})
	lowPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl < zapcore.ErrorLevel
	})

	consoleDebugging := zapcore.Lock(os.Stdout)
	consoleErrors := zapcore.Lock(os.Stderr)

	consoleEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())

	// Join the outputs, encoders, and level-handling functions into
	// zapcore.Cores, then tee the cores together.
	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, consoleErrors, highPriority),
		zapcore.NewCore(consoleEncoder, consoleDebugging, lowPriority),
	)

	// construct a Logger.
	zlogger := zap.New(core)
	zap.ReplaceGlobals(zlogger)

	// slog
	slogger := slog.New(Option{Level: slog.LevelDebug, Logger: zlogger}.NewZapHandler())
	slog.SetDefault(slogger)

	return zlogger, nil

}

func newViperConfig(cmd *cobra.Command, fs afero.Fs, _ *zap.Logger) (*viper.Viper, error) {
	linuxPath := filepath.Join(string(filepath.Separator), "etc", "opensnitchd")
	rulesPath := filepath.Join(string(filepath.Separator), "etc", "opensnitchd", "rules")
	ebpfModPath := filepath.Join(string(filepath.Separator), "usr", "lib", "opensnitchd", "ebpf")
	fwConfigFile := filepath.Join(linuxPath, "system-fw.json")

	v := viper.New()
	v.SetFs(fs)
	v.SetConfigName("default-config.json") // name of config file (without extension)
	v.SetConfigType("json")                // REQUIRED if the config file does not have the extension in the name
	v.AddConfigPath(linuxPath)
	v.AddConfigPath(".")
	err := v.ReadInConfig() // Find and read the config file
	if err != nil {
		return nil, err
	}

	v.SetDefault("workers", 16)
	v.SetDefault("debug", true)
	v.SetDefault("rules.path", rulesPath)
	v.SetDefault("fw-config-file", fwConfigFile)
	v.SetDefault("fw-monitor-duration", 10*time.Second)
	v.SetDefault("ebpf.modulespath", ebpfModPath)

	if flag := cmd.Flags().Lookup("process-monitor-method"); flag != nil {
		if err := v.BindPFlag("process-monitor-method", flag); err != nil {
			return nil, err
		}
	}
	if flag := cmd.Flags().Lookup("ui-socket"); flag != nil {
		if err := v.BindPFlag("ui-socket", flag); err != nil {
			return nil, err
		}
	}
	if flag := cmd.Flags().Lookup("queue-num"); flag != nil {
		if err := v.BindPFlag("queue-num", flag); err != nil {
			return nil, err
		}
	}
	if flag := cmd.Flags().Lookup("workers"); flag != nil {
		if err := v.BindPFlag("workers", flag); err != nil {
			return nil, err
		}
	}
	if flag := cmd.Flags().Lookup("no-live-reload"); flag != nil {
		if err := v.BindPFlag("no-live-reload", flag); err != nil {
			return nil, err
		}
	}
	if flag := cmd.Flags().Lookup("rules-path"); flag != nil {
		if err := v.BindPFlag("rules.paths", flag); err != nil {
			return nil, err
		}
	}
	if flag := cmd.Flags().Lookup("config-file"); flag != nil {
		if err := v.BindPFlag("config-file", flag); err != nil {
			return nil, err
		}
	}
	if flag := cmd.Flags().Lookup("fw-config-file"); flag != nil {
		if err := v.BindPFlag("fw-config-file", flag); err != nil {
			return nil, err
		}
	}
	if flag := cmd.Flags().Lookup("log-file"); flag != nil {
		if err := v.BindPFlag("log-file", flag); err != nil {
			return nil, err
		}
	}
	if flag := cmd.Flags().Lookup("log-utc"); flag != nil {
		if err := v.BindPFlag("log-utc", flag); err != nil {
			return nil, err
		}
	}
	if flag := cmd.Flags().Lookup("log-micro"); flag != nil {
		if err := v.BindPFlag("log-micro", flag); err != nil {
			return nil, err
		}
	}
	if flag := cmd.Flags().Lookup("debug"); flag != nil {
		if err := v.BindPFlag("debug", flag); err != nil {
			return nil, err
		}
	}
	if flag := cmd.Flags().Lookup("warning"); flag != nil {
		if err := v.BindPFlag("warning", flag); err != nil {
			return nil, err
		}
	}
	if flag := cmd.Flags().Lookup("important"); flag != nil {
		if err := v.BindPFlag("important", flag); err != nil {
			return nil, err
		}
	}
	if flag := cmd.Flags().Lookup("error"); flag != nil {
		if err := v.BindPFlag("error", flag); err != nil {
			return nil, err
		}
	}

	return v, nil
}
