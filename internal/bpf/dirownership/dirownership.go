package dirownership

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/msanft/SemanticSanitizer/internal/config"
)

func Attach(conf *config.SanitizerConfig) ([]link.Link, error) {
	objs := dirownershipObjects{}
	if err := loadDirownershipObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load dirownership objects: %w", err)
	}
	defer objs.Close()

	var links []link.Link

	moveMountKprobe, err := link.Kprobe("do_move_mount", objs.UnsafeMoveMountWrapper, nil)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Printf("Attaching do_move_mount kprobe failed: %s. "+
			"This function often gets inlined based on compiler versions. "+
			"Therefore, this failure is not treated as a fatal error", err)
	}
	if moveMountKprobe != nil {
		links = append(links, moveMountKprobe)
	}

	rmdirKprobe, err := link.Kprobe("vfs_rmdir", objs.UnsafeRmdirWrapper, nil)
	if err != nil {
		return nil, fmt.Errorf("attach vfs_rmdir kprobe: %w", err)
	}
	links = append(links, rmdirKprobe)

	chmodKprobe, err := link.Kprobe("chmod_common", objs.UnsafeChmodWrapper, nil)
	if err != nil {
		return nil, fmt.Errorf("attach chmod_common kprobe: %w", err)
	}
	links = append(links, chmodKprobe)

	chownKprobe, err := link.Kprobe("chown_common", objs.UnsafeChownWrapper, nil)
	if err != nil {
		return nil, fmt.Errorf("attach chown_common kprobe: %w", err)
	}
	links = append(links, chownKprobe)

	bprmExecveKprobe, err := link.Kprobe("bprm_execve", objs.UnsafeExecveWrapper, nil)
	if err != nil {
		return nil, fmt.Errorf("attach bprm_execve kprobe: %w", err)
	}
	links = append(links, bprmExecveKprobe)

	return links, nil
}
