package dns

import (
	"debug/elf"
	"errors"
	"fmt"
	log "log/slog"

	bpfElf "github.com/iovisor/gobpf/elf"
)

/*
#cgo LDFLAGS: -ldl

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <link.h>
#include <dlfcn.h>
#include <string.h>

char* find_libc() {
    void *handle;
    struct link_map * map;

    handle = dlopen(NULL, RTLD_NOW);
    if (handle == NULL) {
        fprintf(stderr, "EBPF-DNS dlopen() failed: %s\n", dlerror());
        return NULL;
    }


    if (dlinfo(handle, RTLD_DI_LINKMAP, &map) == -1) {
        fprintf(stderr, "EBPF-DNS: dlinfo failed: %s\n", dlerror());
        return NULL;
    }

    while(1){
        if(map == NULL){
            break;
        }

        if(strstr(map->l_name, "libc.so")){
            fprintf(stderr,"found %s\n", map->l_name);
            return map->l_name;
        }
        map = map->l_next;
    }
    return NULL;
}


*/
import "C"

// LibCPath path to libc.so
func LibCPath() (string, error) {
	ret := C.find_libc()
	if ret == nil {
		return "", errors.New("could not find path to libc.so")
	}

	s := C.GoString(ret)
	return s, nil
}

func OpenELFFile(name string) (*elf.File, error) {
	// libbcc resolves the offsets for us. without bcc the offset for uprobes must parsed from the elf files
	// some how 0 must be replaced with the offset of getaddrinfo bcc does this using bcc_resolve_symname
	libcElf, err := elf.Open(name)
	if err != nil {
		log.Error("EBPF-DNS: failed to open %s: %v", name, err)
		return nil, err
	}

	return libcElf, nil
}

// LoadBPFModule loads the given eBPF module, from the given path if specified.
// Otherwise t'll try to load the module from several default paths.
func LoadBPFModule(fileName string) (m *bpfElf.Module, err error) {
	m = bpfElf.NewModule(fileName)
	if m.Load(nil) == nil {
		log.Info("[eBPF] module loaded", "fileName", fileName)
		return m, nil
	}

	moduleError := fmt.Errorf(`
unable to load eBPF module (%s). Your kernel version (%s) might not be compatible.
If this error persists, change process monitor method to 'proc'`, fileName, GetKernelVersion())

	return nil, moduleError
}

// lookupSymbol iterates over all symbols in an elf file and returns the offset matching the provided symbol name.
func symbolValue(fi *elf.File, symbolName string) (uint64, error) {
	symbols, err := fi.DynamicSymbols()
	if err != nil {
		return 0, err
	}
	for _, symb := range symbols {
		if symb.Name == symbolName {
			return symb.Value, nil
		}
	}

	return 0, fmt.Errorf("symbol '%s' not found", symbolName)
}
