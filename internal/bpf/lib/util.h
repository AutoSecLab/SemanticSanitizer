#ifndef UTIL_H
#define UTIL_H

#define TASK_COMM_LEN 16 // linux/sched.h
#define CONFIG_COMM_KEY 0
#define MAX_ARGSTRING_LEN 256
#define MAX_KERNEL_FUNC_LEN 64

enum context_type {
  CTX_TYPE_SYSCALL = 0,
  CTX_TYPE_KERNEL_FUNC = 1,
  CTX_TYPE_UPROBE = 2,
};

struct context {
  enum context_type type;
  long syscall_id;
  char kernel_func[MAX_KERNEL_FUNC_LEN];
  unsigned long args[6];
  __u32 process_id;
};

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define INIT_SYSCALL_CTX(ctx_ptr, raw_ctx)                                     \
  do {                                                                         \
    (ctx_ptr)->type = CTX_TYPE_SYSCALL;                                        \
    (ctx_ptr)->syscall_id = BPF_CORE_READ(raw_ctx, id);                        \
    (ctx_ptr)->kernel_func[0] = '\0';                                          \
    for (int _i = 0; _i < 6; _i++)                                             \
      BPF_CORE_READ_INTO(&(ctx_ptr)->args[_i], raw_ctx, args[_i]);             \
    (ctx_ptr)->process_id = bpf_get_current_pid_tgid() >> 32;                  \
  } while (0)

#define INIT_KFUNC_CTX(ctx_ptr, func_name)                                     \
  do {                                                                         \
    (ctx_ptr)->type = CTX_TYPE_KERNEL_FUNC;                                    \
    (ctx_ptr)->syscall_id = -1;                                                \
    __builtin_strncpy((ctx_ptr)->kernel_func, func_name,                       \
                      MAX_KERNEL_FUNC_LEN - 1);                                \
    (ctx_ptr)->kernel_func[MAX_KERNEL_FUNC_LEN - 1] = '\0';                    \
    (ctx_ptr)->process_id = bpf_get_current_pid_tgid() >> 32;                  \
  } while (0)

#define INIT_KFUNC_CTX_ARG(ctx_ptr, idx, val)                                  \
  (ctx_ptr)->args[idx] = (unsigned long)(val)

#define INIT_UPROBE_CTX(ctx_ptr, func_name)                                    \
  do {                                                                         \
    (ctx_ptr)->type = CTX_TYPE_UPROBE;                                         \
    (ctx_ptr)->syscall_id = -1;                                                \
    __builtin_strncpy((ctx_ptr)->kernel_func, func_name,                       \
                      MAX_KERNEL_FUNC_LEN - 1);                                \
    (ctx_ptr)->kernel_func[MAX_KERNEL_FUNC_LEN - 1] = '\0';                    \
    (ctx_ptr)->process_id = bpf_get_current_pid_tgid() >> 32;                  \
  } while (0)

#define INIT_SYSCALL_TP_CTX(ctx_ptr, syscall_nr)                               \
  do {                                                                         \
    (ctx_ptr)->type = CTX_TYPE_SYSCALL;                                        \
    (ctx_ptr)->syscall_id = syscall_nr;                                        \
    (ctx_ptr)->kernel_func[0] = '\0';                                          \
    (ctx_ptr)->process_id = bpf_get_current_pid_tgid() >> 32;                  \
  } while (0)

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, char[TASK_COMM_LEN]);
  __uint(max_entries, 1);
} semsan_config SEC(".maps");

static __always_inline int _strncmp(const char *s1, const char *s2, int n) {
  for (int i = 0; i < n; i++) {
    if (s1[i] == '\0' || s2[i] == '\0')
      break;
    if (s1[i] != s2[i])
      return 1;
  }
  return 0;
}

static __always_inline int _strstr(const char *haystack, const char *needle,
                                   int max_len) {
  for (int i = 0; i < max_len - 1; i++) {
    if (haystack[i] == '\0')
      return -1;

    int match = 1;
    for (int j = 0; j < MAX_ARGSTRING_LEN && needle[j] != '\0'; j++) {
      if (i + j >= max_len || haystack[i + j] != needle[j]) {
        match = 0;
        break;
      }
    }
    if (match)
      return i;
  }
  return -1;
}

/*
is_expected_comm checks if the current task's comm is equal to the expected
comm.
Returns 0 if the comms are equal, 1 if they are not, and -1 if an error occurs.
*/
static __always_inline int is_expected_comm() {
  char actual_comm[TASK_COMM_LEN];
  if (bpf_get_current_comm(actual_comm, sizeof(actual_comm)) < 0)
    return -1;

  __u32 key = CONFIG_COMM_KEY;
  char *expected_comm = bpf_map_lookup_elem(&semsan_config, &key);
  if (expected_comm == NULL)
    return -1;

  if (expected_comm[0] == '*' && expected_comm[1] == '\0')
    return 0;

  return _strncmp(expected_comm, actual_comm, TASK_COMM_LEN);
}

/*
term_action performs the termination action for the task.
*/
static __always_inline int term_action() {
  if (bpf_send_signal_thread(SIGKILL) < 0)
    return -1;

  return 0;
}

static __always_inline int map_update(void *map, const void *key,
                                      const void *value, __u64 flags) {
  return bpf_map_update_elem(map, key, value, flags);
}

static __always_inline void *map_fetch(void *map, const void *key) {
  return bpf_map_lookup_elem(map, key);
}

static __always_inline int glob(const char *str, const char *pattern,
                                int max_len) {
  int si = 0, pi = 0;
  int star = -1, match = 0;

  for (int i = 0; i < max_len && str[si] != '\0'; i++) {
    if (pi < max_len && pattern[pi] == '*') {
      star = pi++;
      match = si;
    } else if (pi < max_len && (pattern[pi] == '?' || pattern[pi] == str[si])) {
      pi++;
      si++;
    } else if (star >= 0) {
      pi = star + 1;
      si = ++match;
    } else {
      return 0;
    }
  }

  for (int i = 0; i < max_len && pattern[pi] == '*'; i++)
    pi++;

  return pattern[pi] == '\0';
}

static __always_inline int get_kstack_trace(void *ctx, void *map, __u64 flags) {
  return bpf_get_stackid(ctx, map, flags | BPF_F_KERNEL_STACK);
}

static __always_inline int get_ustack_trace(void *ctx, void *map, __u64 flags) {
  return bpf_get_stackid(ctx, map, flags | BPF_F_USER_STACK);
}

struct ns_info {
  __u32 pid_ns;
  __u32 mnt_ns;
  __u32 net_ns;
  __u32 uts_ns;
};

static __always_inline int get_current_namespaces(struct ns_info *ns) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  if (!task)
    return -1;

  ns->pid_ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
  ns->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
  ns->net_ns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
  ns->uts_ns = BPF_CORE_READ(task, nsproxy, uts_ns, ns.inum);

  return 0;
}

static __always_inline int match_canary(const char *haystack,
                                        const char *needle, int max_len) {
  return _strstr(haystack, needle, max_len) >= 0;
}

#endif
