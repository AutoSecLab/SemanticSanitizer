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

SEC("tracepoint/raw_syscalls/sys_enter")
int canary_filter_wrapper(struct trace_event_raw_sys_enter *raw_ctx) {
  // Fast path: check if this syscall has a canary rule before doing
  // expensive work (comm check, arg reads, string matching).
  long raw_id = BPF_CORE_READ(raw_ctx, id);
  __u32 syscall_id = (__u32)raw_id;
  struct canary_rule *rule = bpf_map_lookup_elem(&canaries, &syscall_id);
  if (rule == NULL || rule->disallowed_str[0] == '\0')
    return 0;

  if (is_expected_comm() != 0)
    return 0;

  // Read only the argument we need, using constant indices for CO-RE.
  unsigned long arg_ptr;
  switch (rule->arg_idx) {
  case 0:
    BPF_CORE_READ_INTO(&arg_ptr, raw_ctx, args[0]);
    break;
  case 1:
    BPF_CORE_READ_INTO(&arg_ptr, raw_ctx, args[1]);
    break;
  case 2:
    BPF_CORE_READ_INTO(&arg_ptr, raw_ctx, args[2]);
    break;
  case 3:
    BPF_CORE_READ_INTO(&arg_ptr, raw_ctx, args[3]);
    break;
  case 4:
    BPF_CORE_READ_INTO(&arg_ptr, raw_ctx, args[4]);
    break;
  case 5:
    BPF_CORE_READ_INTO(&arg_ptr, raw_ctx, args[5]);
    break;
  default:
    return 0;
  }

  if (arg_ptr == 0)
    return 0;

  char buf[MAX_ARGSTRING_LEN];
  long ret = bpf_probe_read_user_str(buf, sizeof(buf), (void *)arg_ptr);
  if (ret < 0)
    return 0;

  int pos = _strstr(buf, rule->disallowed_str, MAX_ARGSTRING_LEN);
  if (pos >= 0) {
    bpf_printk(
        "canary: detected disallowed substring %s in arg %d of syscall %u\n",
        rule->disallowed_str, rule->arg_idx, syscall_id);
    term_action();
  }

  return 0;
}
