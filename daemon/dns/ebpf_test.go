package dns

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestLibCPath(t *testing.T) {
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(h))

	path, err := LibCPath()
	if err != nil {
		t.Fatal(err)
	}

	if path == "" {
		t.Errorf("path not found")
	}
}

func TestOpenELFFile(t *testing.T) {
	name, err := LibCPath()
	if err != nil {
		t.Fatal(err)
	}

	fi, err := OpenELFFile(name)
	if err != nil {
		t.Fatal(err)
	}

	if err := fi.Close(); err != nil {
		t.Error(err)
	}
}

func TestLoadBPFModule(t *testing.T) {
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(h))

	fileName := filepath.Join(string(filepath.Separator), "usr", "lib", "opensnitchd", "ebpf", "opensnitch-dns.o")
	m, err := LoadBPFModule(fileName)
	if err != nil {
		t.Fatal(err)
	}

	m.Close()
}

func TestListenereBPF(t *testing.T) {
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(h))

	ctx, cancel := context.WithCancel(context.Background())

	err := ListenerEBPF(ctx)
	if err != nil {
		t.Fatal(err)
	}

	cancel()
}
