package symlinkmount

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/msanft/SemanticSanitizer/internal/config"
)

func Attach(conf *config.SanitizerConfig) ([]link.Link, error) {
	objs := symlinkmountObjects{}
	if err := loadSymlinkmountObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load symlinkmount objects: %w", err)
	}
	defer objs.Close()

	// TODO: move this out of here
	comm := []byte(conf.Comm + strings.Repeat("\x00", 16-len(conf.Comm)))
	if err := objs.symlinkmountMaps.SemsanConfig.Put(uint32(0), comm); err != nil {
		return nil, fmt.Errorf("put config: %w", err)
	}

	kp, err := link.Kprobe("vfs_symlink", objs.TraceVfsSymlinkWrapper, nil)
	if err != nil {
		return nil, fmt.Errorf("attach kprobe: %w", err)
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_mount", objs.SymlinkMountWrapper, nil)
	if err != nil {
		return nil, fmt.Errorf("attach to tracepoint: %w", err)
	}

	return []link.Link{kp, tp}, nil
}
