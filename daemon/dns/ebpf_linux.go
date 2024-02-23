package dns

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	log "log/slog"
	"net"
	"os"
	"strings"

	bpfElf "github.com/iovisor/gobpf/elf"
	"golang.org/x/sync/errgroup"
)

const (
	defaultModuleFileName = "/usr/lib/opensnitchd/ebpf/opensnitch-dns.o"
)

type nameLookupEvent struct {
	AddrType uint32
	IP       [16]uint8
	Host     [252]byte
}

type Config struct {
	ModuleFileName string         // ModuleFileName full path to module file 'opensnitchd.so'
	Module         *bpfElf.Module // opensnitch bcc module

	LibCFileName string    // LibCELF path to libc.so
	LibCELF      *elf.File // LibCELFFile lib c elf file

	CallbackFn CallbackFunc
}

type CallbackFunc func(ctx context.Context, ip net.IP, host string)

type Option func(*Config)

func NewConfigWithOptions(options ...Option) (Config, error) {
	cfg := &Config{
		ModuleFileName: defaultModuleFileName,
	}

	for _, opt := range options {
		opt(cfg)
	}

	if cfg.Module == nil {
		module, err := LoadBPFModule(cfg.ModuleFileName)
		if err != nil {
			return Config{}, err
		}
		cfg.Module = module
	}

	if cfg.LibCFileName == "" {
		libcFile, err := LibCPath()
		if err != nil {
			return Config{}, err
		}
		cfg.LibCFileName = libcFile
	}

	if cfg.LibCELF == nil {
		libcElf, err := OpenELFFile(cfg.LibCFileName)
		if err != nil {
			return Config{}, err
		}

		cfg.LibCELF = libcElf
	}

	return *cfg, nil
}

func WithModuleFileName(fileName string) Option {
	return func(c *Config) {
		c.ModuleFileName = fileName
	}
}

func WithELFModule(module *bpfElf.Module) Option {
	return func(c *Config) {
		c.Module = module
	}
}

func WithLibCFileName(fileName string) Option {
	return func(c *Config) {
		c.LibCFileName = fileName
	}
}

func WithLibCELF(fi *elf.File) Option {
	return func(c *Config) {
		c.LibCELF = fi
	}
}

func WithCallbackFunc(callbackFn CallbackFunc) Option {
	return func(c *Config) {
		c.CallbackFn = callbackFn
	}
}

// ListenerEBPF starts listening for DNS events.
func ListenerEBPF(ctx context.Context, option ...Option) error {
	cfg, err := NewConfigWithOptions(option...)
	if err != nil {
		return err
	}
	defer cfg.Module.Close()

	if err := attachProbes(cfg.Module, cfg.LibCFileName, cfg.LibCELF); err != nil {
		return err
	}

	if err := ebpfDNSPerfMapListener(ctx, cfg.Module, cfg.LibCELF, cfg.CallbackFn); err != nil {
		return err
	}

	return nil
}

func attachProbes(module *bpfElf.Module, LibCFileName string, libcElf *elf.File) error {
	// libbcc resolves the offsets for us. without bcc the offset for uprobes must parsed from the elf files
	// some how 0 must be replaced with the offset of getaddrinfo bcc does this using bcc_resolve_symname

	// Attaching to uprobe using perf open might be a better aproach requires https://github.com/iovisor/gobpf/pull/277
	probesAttached := 0
	for uprobe := range module.IterUprobes() {
		probeFunction := strings.Replace(uprobe.Name, "uretprobe/", "", 1)
		probeFunction = strings.Replace(probeFunction, "uprobe/", "", 1)
		offset, err := symbolValue(libcElf, probeFunction)
		if err != nil {
			log.Warn("EBPF-DNS: failed to find symbol for uprobe", slog.Group("uprobe", "name", uprobe.Name, "offset", offset), "error", err)
			continue
		}
		err = bpfElf.AttachUprobe(uprobe, LibCFileName, offset)
		if err != nil {
			log.Warn("EBPF-DNS: failed to attach uprobe", slog.Group("uprobe", "name", uprobe.Name, "offset", offset), "libc.file", LibCFileName, "error", err)
			continue
		}
		probesAttached++
	}

	if probesAttached == 0 {
		log.Warn("EBPF-DNS: failed to find symbols for uprobes")
		return errors.New("failed to find symbols for uprobes")
	}

	return nil
}

func ebpfDNSPerfMapListener(ctx context.Context, m *bpfElf.Module, fi *elf.File, callbackFn CallbackFunc) error {
	perfMapEventReceiverCh := make(chan []byte)
	perfMap, err := bpfElf.InitPerfMap(m, "events", perfMapEventReceiverCh, nil)
	if err != nil {
		log.Error("EBPF-DNS: Failed to init perf map: %s\n", err)
		return err
	}

	var eg errgroup.Group
	eg.Go(func() error {
		return perfMapReceiver(ctx, perfMapEventReceiverCh, callbackFn)
	})

	perfMap.PollStart()

	if err := eg.Wait(); err != nil {
		// can return context cancelled error
		return err
	}

	log.Info("EBPF-DNS: closing ebpf dns hook")

	perfMap.PollStop()

	close(perfMapEventReceiverCh)

	return nil
}

// perfMapReceiver receive data over channel
// exit on context.Done or reciever chan close
func perfMapReceiver(ctx context.Context, receiverCh chan []byte, callbackFn CallbackFunc) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case data, chanOpen := <-receiverCh:
			if !chanOpen {
				log.Debug("receiver chan closed")
				return nil
			}

			if len(data) == 0 {
				log.Debug("EBPF-DNS: no data received on LookupEvent")
				continue
			}

			log.Debug("EBPF-DNS: LookupEvent", "data.len", len(data), "data", fmt.Sprintf("%x %x %x", data[:4], data[4:20], data[20:]))

			var event nameLookupEvent
			var ip net.IP
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				// TODO: create errChan and goroutine to receive errors
				log.Warn(" EBPF-DNS: Failed to decode ebpf nameLookupEvent", "id", id, "error", err)
				continue
			}
			// Convert C string (null-terminated) to Go string
			host := string(event.Host[:bytes.IndexByte(event.Host[:], 0)])
			// 2 -> AF_INET (ipv4)
			if event.AddrType == 2 {
				ip = net.IP(event.IP[:4])
			} else {
				ip = net.IP(event.IP[:])
			}

			log.Debug("EBPF-DNS: received message", "host", host, "ip", ip.String())
			callbackFn(ctx, ip, host)
		}
	}
}

// GetKernelVersion returns the kernel version.
func GetKernelVersion() string {
	version, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	return strings.Replace(string(version), "\n", "", -1)
}
