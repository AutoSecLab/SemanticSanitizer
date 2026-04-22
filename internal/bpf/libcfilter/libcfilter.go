package libcfilter

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/msanft/SemanticSanitizer/internal/bpf"
	"github.com/msanft/SemanticSanitizer/internal/config"
)

func Attach(conf *config.SanitizerConfig) ([]link.Link, error) {
	objs := libcfilterObjects{}
	if err := loadLibcfilterObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load libcfilter objects: %w", err)
	}
	defer objs.Close()

	if err := objs.libcfilterMaps.SemsanConfig.Put(uint32(0), bpf.EncodeComm(conf.Comm)); err != nil {
		return nil, fmt.Errorf("put config: %w", err)
	}

	ex, err := link.OpenExecutable(conf.BinaryPath)
	if err != nil {
		return nil, fmt.Errorf("open executable: %w", err)
	}

	up, err := ex.Uprobe("__gets_chk", objs.LibcFilterWrapper, &link.UprobeOptions{})
	if err != nil {
		return nil, fmt.Errorf("attach uprobe: %w", err)
	}

	return []link.Link{up}, nil
}
