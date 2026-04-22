package syscallfilter

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/msanft/SemanticSanitizer/internal/bpf"
	"github.com/msanft/SemanticSanitizer/internal/config"
)

const syscallDisallowed = uint8(1)

func Attach(conf *config.SanitizerConfig) ([]link.Link, error) {
	objs := syscallfilterObjects{}
	if err := loadSyscallfilterObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load syscallfilter objects: %w", err)
	}
	defer objs.Close()

	if err := objs.syscallfilterMaps.SemsanConfig.Put(uint32(0), bpf.EncodeComm(conf.Comm)); err != nil {
		return nil, fmt.Errorf("put config: %w", err)
	}

	for _, sc := range conf.Syscalls {
		if err := objs.syscallfilterMaps.DisallowedSyscalls.Put(uint32(sc.Number), syscallDisallowed); err != nil {
			return nil, fmt.Errorf("put disallowed syscall: %w", err)
		}
	}

	kp, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.SyscallFilterWrapper, nil)
	if err != nil {
		return nil, fmt.Errorf("attach to tracepoint: %w", err)
	}

	return []link.Link{kp}, nil
}
