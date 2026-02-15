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

static __always_inline unsigned char is_root() {
  __u64 gid_uid = bpf_get_current_uid_gid();
  __u32 uid = gid_uid & 0xFFFFFFFF;
  __u32 gid = gid_uid >> 32;
  if (uid == 0 || gid == 0) {
    return 1;
  }
  return 0;
}

static __always_inline unsigned char is_inode_root_owned(struct inode *inode) {
  __u32 uid = BPF_CORE_READ(inode, i_uid.val);
  __u32 gid = BPF_CORE_READ(inode, i_gid.val);

  if (uid == 0 || gid == 0) {
    return 1;
  }

  return 0;
}

static __always_inline char is_parent_root_owned(struct dentry *dentry) {
  struct inode *inode = BPF_CORE_READ(dentry, d_parent, d_inode);
  if (inode == NULL) {
    bpf_printk("could not get parent inode\n");
    return -22; // EINVAL
  }

  return is_inode_root_owned(inode);
}

static __always_inline int unsafe_move_mount_filter(struct context *sctx) {
  struct path *path = (struct path *)sctx->args[0];
  struct dentry *dentry = BPF_CORE_READ(path, dentry);
  if (dentry == NULL)
    return 0;

  const unsigned char *filename = BPF_CORE_READ(dentry, d_name.name);

  if (is_parent_root_owned(dentry) == 0) {
    bpf_printk("Unsafe mount move by root user: %s\n", filename);
    term_action();
  }

  return 0;
}

SEC("kprobe/do_move_mount")
int BPF_KPROBE(unsafe_move_mount_wrapper, struct path *old_path,
               struct path *new_path, char beneath) {
  if (is_root() == 0)
    return 0;

  struct context sctx;
  INIT_KFUNC_CTX(&sctx, "do_move_mount");
  INIT_KFUNC_CTX_ARG(&sctx, 0, old_path);
  INIT_KFUNC_CTX_ARG(&sctx, 1, new_path);
  INIT_KFUNC_CTX_ARG(&sctx, 2, beneath);

  return unsafe_move_mount_filter(&sctx);
}

// TODO(msanft): Add a sanitizer for bind mounts in the old mount API.
// Somehow ebpf-go doesn't want us to attach to `__do_loopback`.

static __always_inline int unsafe_chmod_filter(struct context *sctx) {
  const struct path *path = (const struct path *)sctx->args[0];
  struct dentry *dentry = BPF_CORE_READ(path, dentry);
  if (dentry == NULL)
    return 0;

  const unsigned char *filename = BPF_CORE_READ(dentry, d_name.name);

  if (is_parent_root_owned(dentry) == 0) {
    bpf_printk("Unsafe chmod by root user: %s\n", filename);
    term_action();
  }

  return 0;
}

SEC("kprobe/chmod_common")
int BPF_KPROBE(unsafe_chmod_wrapper, const struct path *path, umode_t mode) {
  if (is_root() == 0)
    return 0;

  struct context sctx;
  INIT_KFUNC_CTX(&sctx, "chmod_common");
  INIT_KFUNC_CTX_ARG(&sctx, 0, path);
  INIT_KFUNC_CTX_ARG(&sctx, 1, mode);

  return unsafe_chmod_filter(&sctx);
}

static __always_inline int unsafe_chown_filter(struct context *sctx) {
  const struct path *path = (const struct path *)sctx->args[0];
  struct dentry *dentry = BPF_CORE_READ(path, dentry);
  if (dentry == NULL)
    return 0;

  const unsigned char *filename = BPF_CORE_READ(dentry, d_name.name);

  if (is_parent_root_owned(dentry) == 0) {
    bpf_printk("Unsafe chown by root user: %s\n", filename);
    term_action();
  }

  return 0;
}

SEC("kprobe/chown_common")
int BPF_KPROBE(unsafe_chown_wrapper, const struct path *path, uid_t user,
               gid_t group) {
  if (is_root() == 0)
    return 0;

  struct context sctx;
  INIT_KFUNC_CTX(&sctx, "chown_common");
  INIT_KFUNC_CTX_ARG(&sctx, 0, path);
  INIT_KFUNC_CTX_ARG(&sctx, 1, user);
  INIT_KFUNC_CTX_ARG(&sctx, 2, group);

  return unsafe_chown_filter(&sctx);
}

static __always_inline int unsafe_rmdir_filter(struct context *sctx) {
  struct inode *dir_inode = (struct inode *)sctx->args[1];
  if (dir_inode == NULL)
    return 0;

  struct dentry *d = (struct dentry *)sctx->args[2];
  const unsigned char *filename = BPF_CORE_READ(d, d_name.name);

  if (is_inode_root_owned(dir_inode) == 0) {
    bpf_printk("Unsafe rmdir by root user: %s\n", filename);
    term_action();
  }

  return 0;
}

SEC("kprobe/vfs_rmdir")
int BPF_KPROBE(unsafe_rmdir_wrapper, void *idmap, struct inode *dir,
               struct dentry *dentry) {
  if (is_root() == 0)
    return 0;

  struct context sctx;
  INIT_KFUNC_CTX(&sctx, "vfs_rmdir");
  INIT_KFUNC_CTX_ARG(&sctx, 0, idmap);
  INIT_KFUNC_CTX_ARG(&sctx, 1, dir);
  INIT_KFUNC_CTX_ARG(&sctx, 2, dentry);

  return unsafe_rmdir_filter(&sctx);
}

// TODO(msanft): Make this work with symlinks.
// Unfortunately, the current implementation hooks *after* the path is resolved,
// meaning that a situation where `some-user-owned-dir/symlink-to-bin-foo` is
// executed by root will not be detected if `/bin` (where `/bin/foo` is located)
// is owned by root.

static __always_inline int unsafe_execve_filter(struct context *sctx) {
  struct linux_binprm *b = (struct linux_binprm *)sctx->args[0];
  struct file *file = BPF_CORE_READ(b, file);
  if (file == NULL)
    return 0;

  struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
  if (dentry == NULL)
    return 0;

  const char *filename = BPF_CORE_READ(b, filename);

  if (is_parent_root_owned(dentry) == 0) {
    bpf_printk("Unsafe execve by root user: %s\n", filename);
    term_action();
  }

  return 0;
}

SEC("kprobe/bprm_execve")
int BPF_KPROBE(unsafe_execve_wrapper, struct linux_binprm *bprm) {
  if (is_root() == 0)
    return 0;

  struct context sctx;
  INIT_KFUNC_CTX(&sctx, "bprm_execve");
  INIT_KFUNC_CTX_ARG(&sctx, 0, bprm);

  return unsafe_execve_filter(&sctx);
}
