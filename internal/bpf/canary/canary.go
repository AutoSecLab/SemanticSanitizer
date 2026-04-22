package canary

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/msanft/SemanticSanitizer/internal/bpf"
	"github.com/msanft/SemanticSanitizer/internal/config"
	"golang.org/x/sys/unix"
)

const maxStringLen = 256

type canaryRule struct {
	ArgIdx        uint32
	DisallowedStr [maxStringLen]byte
}

func Attach(conf *config.SanitizerConfig) ([]link.Link, error) {
	objs := canaryObjects{}
	if err := loadCanaryObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load canary objects: %w", err)
	}
	defer objs.Close()

	if err := objs.canaryMaps.SemsanConfig.Put(uint32(0), bpf.EncodeComm(conf.Comm)); err != nil {
		return nil, fmt.Errorf("put config: %w", err)
	}

	rules := make(map[uint32]canaryRule)
	for sc, scConf := range conf.Canary {
		syscallNum, err := getSyscallNumber(sc)
		if err != nil {
			return nil, fmt.Errorf("get syscall number for %s: %w", sc, err)
		}

		var disallowedStr [maxStringLen]byte
		copy(disallowedStr[:], scConf.Substring)

		rule := canaryRule{
			ArgIdx:        uint32(scConf.ArgIndex),
			DisallowedStr: disallowedStr,
		}

		rules[uint32(syscallNum)] = rule
	}

	for syscallNum, rule := range rules {
		if err := objs.canaryMaps.Canaries.Put(syscallNum, rule); err != nil {
			return nil, fmt.Errorf("put canary rules for syscall %d: %w", syscallNum, err)
		}
	}

	kp, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.CanaryFilterWrapper, nil)
	if err != nil {
		return nil, fmt.Errorf("attach to tracepoint: %w", err)
	}

	return []link.Link{kp}, nil
}

func getSyscallNumber(name string) (int, error) {
	syscallMap := map[string]int{
		"read":     unix.SYS_READ,
		"write":    unix.SYS_WRITE,
		"open":     unix.SYS_OPEN,
		"openat":   unix.SYS_OPENAT,
		"execve":   unix.SYS_EXECVE,
		"execveat": unix.SYS_EXECVEAT,
	}

	num, ok := syscallMap[name]
	if !ok {
		return 0, fmt.Errorf("unknown syscall: %s", name)
	}
	return num, nil
}
