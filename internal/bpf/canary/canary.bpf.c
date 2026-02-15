//go:build ignore

#define __TARGET_ARCH_x86

#include "../lib/vmlinux.h" // IWYU pragma: keep

#include <linux/types.h>
#include <linux/limits.h>
#include <linux/stat.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "../lib/util.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct trace_event_raw_sys_enter {
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;
  long id;
  unsigned long args[6];
};

struct canary_rule {
  __u32 arg_idx;
  char disallowed_str[MAX_ARGSTRING_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct canary_rule);
  __uint(max_entries, 400);
} canaries SEC(".maps");

static __always_inline int canary_filter(struct context *sctx) {
  struct canary_rule *rule = bpf_map_lookup_elem(&canaries, &sctx->syscall_id);
  if (rule == NULL || *rule->disallowed_str == '\0')
    return 1;

  __u32 arg_idx = rule->arg_idx;
  if (arg_idx >= 6)
    return 0;

  unsigned long arg_ptr = sctx->args[arg_idx];
  if (arg_ptr == 0)
    return 0;

  char buf[MAX_ARGSTRING_LEN];
  long ret = bpf_probe_read_user_str(buf, sizeof(buf), (void *)arg_ptr);
  if (ret < 0)
    return 0;

  int pos = _strstr(buf, rule->disallowed_str, MAX_ARGSTRING_LEN);
  if (pos >= 0) {
    bpf_printk(
        "canary: detected disallowed substring %s in arg %d of syscall %ld\n",
        rule->disallowed_str, arg_idx, sctx->syscall_id);
    term_action();
    return 0;
  }

  return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int canary_filter_wrapper(struct trace_event_raw_sys_enter *raw_ctx) {
  if (is_expected_comm() != 0)
    return 1;

  struct context sctx;
  INIT_SYSCALL_CTX(&sctx, raw_ctx);

  return canary_filter(&sctx);
}
