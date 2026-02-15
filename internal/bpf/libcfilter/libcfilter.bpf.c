//go:build ignore

#include "../lib/vmlinux.h" // IWYU pragma: keep
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "../lib/util.h"

char __license[] SEC("license") = "Dual MIT/GPL";

static __always_inline int libc_filter(struct context *sctx) {
  term_action();

  return 0;
}

SEC("uprobe/libc:__gets_chk")
int libc_filter_wrapper(struct pt_regs *raw_ctx) {
  if (is_expected_comm() != 0)
    return 1;

  struct context sctx;
  INIT_UPROBE_CTX(&sctx, "__gets_chk");

  return libc_filter(&sctx);
}
