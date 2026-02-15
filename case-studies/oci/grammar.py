ctx.rule("START", "{OCI_CONFIG}")

# Top-level config structure with linux section
ctx.script(
    "OCI_CONFIG",
    ["OCI_VERSION", "PLATFORM", "PROCESS", "ROOT", "LINUX", "MOUNTS", "ANNOTATIONS"],
    lambda version, platform, process, root, linux, mounts, annotations: b"{%s,%s,%s,%s,%s,%s,%s}"
    % (version, platform, process, root, linux, mounts, annotations),
)

# OCI Version field
ctx.rule("OCI_VERSION", '"ociVersion": "{VERSION_NUMBER}"')
ctx.rule("VERSION_NUMBER", "1.0.0")
ctx.rule("VERSION_NUMBER", "1.1.0")
ctx.rule("VERSION_NUMBER", "1.2.0")
ctx.regex("VERSION_NUMBER", "[0-9]+\\.[0-9]+\\.[0-9]+")

# Platform field
ctx.script(
    "PLATFORM",
    ["OS_NAME", "ARCH_NAME"],
    lambda os, arch: b'"platform": {"os": "%s","arch": "%s"}' % (os, arch),
)

ctx.rule("OS_NAME", "linux")
ctx.rule("ARCH_NAME", "amd64")
ctx.rule("ARCH_NAME", "arm64")

# Process field
ctx.script(
    "PROCESS",
    ["TERMINAL_VAL", "USER_CONFIG", "ARGS_LIST", "ENV_LIST", "CWD_VAL"],
    lambda terminal, user, args, env, cwd: b'"process": {"terminal": %s,%s,%s,%s,"cwd": "%s"}'
    % (terminal, user, args, env, cwd),
)

# ctx.rule("TERMINAL_VAL", "true")
ctx.rule("TERMINAL_VAL", "false")

ctx.script(
    "USER_CONFIG",
    ["UID_VAL", "GID_VAL"],
    lambda uid, gid: b'"user": {"uid": %s,"gid": %s}' % (uid, gid),
)

ctx.rule("UID_VAL", "0")
ctx.rule("UID_VAL", "1000")
ctx.rule("UID_VAL", "1001")
ctx.regex("UID_VAL", "[1-9][0-9]+")

ctx.rule("GID_VAL", "0")
ctx.rule("GID_VAL", "1000")
ctx.rule("GID_VAL", "1001")
ctx.regex("GID_VAL", "[1-9][0-9]+")

ctx.rule("ARGS_LIST", '"args": ["/bin/sh"]')
ctx.rule("ARGS_LIST", '"args": ["/bin/bash"]')
ctx.rule("ARGS_LIST", '"args": ["./app"]')
ctx.rule("ARGS_LIST", '"args": ["/usr/bin/nginx", "-g", "daemon off;"]')

ctx.rule(
    "ENV_LIST",
    '"env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]',
)
ctx.rule(
    "ENV_LIST",
    '"env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TERM=xterm"]',
)

ctx.rule("CWD_VAL", "/")
ctx.rule("CWD_VAL", "/app")
ctx.rule("CWD_VAL", "/home/user")

# Root field
ctx.script(
    "ROOT",
    ["ROOT_PATH", "READONLY_VAL"],
    lambda path, readonly: b'"root": {"path": "%s","readonly": %s}' % (path, readonly),
)

ctx.rule("ROOT_PATH", "rootfs")

ctx.rule("READONLY_VAL", "false")
ctx.rule("READONLY_VAL", "true")

# =============================================================================
# LINUX SECTION
# =============================================================================

# Main Linux configuration
ctx.script(
    "LINUX",
    ["NAMESPACES", "RESOURCES", "SECCOMP", "SYSCTL", "PATH_SECURITY"],
    lambda ns, res, sec, sysctl, paths: b'"linux": {%s,%s,%s,%s,%s}'
    % (ns, res, sec, sysctl, paths),
)

# Alternative Linux config with different combinations
ctx.script(
    "LINUX",
    ["NAMESPACES", "DEVICES", "CGROUPS_PATH"],
    lambda ns, dev, cpath: b'"linux": {%s,%s,%s}' % (ns, dev, cpath),
)

ctx.script(
    "LINUX",
    ["RESOURCES", "ID_MAPPINGS", "ROOTFS_PROPAGATION"],
    lambda res, idmap, rfsprop: b'"linux": {%s,%s,%s}' % (res, idmap, rfsprop),
)

# Namespaces configuration
ctx.rule("NAMESPACES", '"namespaces": []')
ctx.script(
    "NAMESPACES",
    ["NAMESPACE_LIST"],
    lambda nslist: b'"namespaces": [%s]' % nslist,
)

ctx.script(
    "NAMESPACE_LIST",
    ["NAMESPACE_ITEM"],
    lambda ns: ns,
)

ctx.script(
    "NAMESPACE_LIST",
    ["NAMESPACE_ITEM", "NAMESPACE_LIST"],
    lambda ns1, nslist: b'%s,%s' % (ns1, nslist),
)

ctx.script(
    "NAMESPACE_ITEM",
    ["NAMESPACE_TYPE"],
    lambda nstype: b'{"type": "%s"}' % nstype,
)

ctx.rule("NAMESPACE_TYPE", "pid")
ctx.rule("NAMESPACE_TYPE", "network")
ctx.rule("NAMESPACE_TYPE", "mount")
ctx.rule("NAMESPACE_TYPE", "ipc")
ctx.rule("NAMESPACE_TYPE", "uts")
ctx.rule("NAMESPACE_TYPE", "user")
ctx.rule("NAMESPACE_TYPE", "cgroup")

# Resources (cgroups) configuration
ctx.script(
    "RESOURCES",
    ["MEMORY_CONFIG", "CPU_LIMIT", "PIDS_LIMIT"],
    lambda mem, cpu, pids: b'"resources": {%s,%s,%s}' % (mem, cpu, pids),
)

ctx.script(
    "RESOURCES",
    ["MEMORY_CONFIG"],
    lambda mem: b'"resources": {%s}' % mem,
)

ctx.script(
    "RESOURCES",
    ["CPU_CONFIG"],
    lambda cpu: b'"resources": {%s}' % cpu,
)

# Memory configuration
ctx.script(
    "MEMORY_CONFIG",
    ["MEMORY_LIMIT"],
    lambda limit: b'"memory": {"limit": %s}' % limit,
)

ctx.script(
    "MEMORY_CONFIG",
    ["MEMORY_LIMIT", "MEMORY_SWAP"],
    lambda limit, swap: b'"memory": {"limit": %s,"swap": %s}' % (limit, swap),
)

ctx.script(
    "MEMORY_CONFIG",
    ["MEMORY_LIMIT", "MEMORY_RESERVATION", "MEMORY_SWAPPINESS"],
    lambda limit, res, swap: b'"memory": {"limit": %s,"reservation": %s,"swappiness": %s}' % (limit, res, swap),
)

ctx.regex("MEMORY_LIMIT", "[0-9]+")

ctx.rule("MEMORY_SWAP", "268435456")    # 256MB
ctx.rule("MEMORY_SWAP", "536870912")    # 512MB
ctx.rule("MEMORY_SWAP", "1073741824")   # 1GB

ctx.rule("MEMORY_RESERVATION", "67108864")  # 64MB
ctx.rule("MEMORY_RESERVATION", "134217728") # 128MB

ctx.rule("MEMORY_SWAPPINESS", "60")
ctx.rule("MEMORY_SWAPPINESS", "10")
ctx.rule("MEMORY_SWAPPINESS", "0")

# CPU configuration
ctx.script(
    "CPU_CONFIG",
    ["CPU_SHARES"],
    lambda shares: b'"cpu": {"shares": %s}' % shares,
)

ctx.script(
    "CPU_CONFIG",
    ["CPU_SHARES", "CPU_PERIOD", "CPU_QUOTA"],
    lambda shares, period, quota: b'"cpu": {"shares": %s,"period": %s,"quota": %s}' % (shares, period, quota),
)

ctx.script(
    "CPU_CONFIG",
    ["CPU_CPUS"],
    lambda cpus: b'"cpu": {"cpus": "%s"}' % cpus,
)

ctx.rule("CPU_LIMIT", '"cpu": \{"shares": 1024\}')
ctx.rule("CPU_LIMIT", '"cpu": \{"shares": 512\}')
ctx.rule("CPU_LIMIT", '"cpu": \{"period": 100000,"quota": 50000\}')

ctx.rule("CPU_SHARES", "1024")
ctx.rule("CPU_SHARES", "512")
ctx.rule("CPU_SHARES", "256")
ctx.rule("CPU_SHARES", "2048")

ctx.rule("CPU_PERIOD", "100000")
ctx.rule("CPU_PERIOD", "50000")

ctx.rule("CPU_QUOTA", "50000")
ctx.rule("CPU_QUOTA", "25000")
ctx.rule("CPU_QUOTA", "-1")

ctx.rule("CPU_CPUS", "0-1")
ctx.rule("CPU_CPUS", "0,2")
ctx.rule("CPU_CPUS", "0-3")

# PIDs limit
ctx.rule("PIDS_LIMIT", '"pids": \{"limit": 1024\}')
ctx.rule("PIDS_LIMIT", '"pids": \{"limit": 512\}')
ctx.rule("PIDS_LIMIT", '"pids": \{"limit": 2048\}')
ctx.rule("PIDS_LIMIT", '"pids": \{"limit": -1\}')

# Devices configuration
ctx.rule("DEVICES", '"devices": []')
ctx.script(
    "DEVICES",
    ["DEVICE_LIST"],
    lambda devlist: b'"devices": [%s]' % devlist,
)

ctx.script(
    "DEVICE_LIST",
    ["DEVICE_ITEM"],
    lambda dev: dev,
)

ctx.script(
    "DEVICE_LIST",
    ["DEVICE_ITEM", "DEVICE_LIST"],
    lambda dev1, devlist: b'%s,%s' % (dev1, devlist),
)

ctx.script(
    "DEVICE_ITEM",
    ["DEVICE_PATH", "DEVICE_TYPE", "DEVICE_MAJOR", "DEVICE_MINOR"],
    lambda path, dtype, major, minor: b'{"path": "%s","type": "%s","major": %s,"minor": %s}' % (path, dtype, major, minor),
)

ctx.rule("DEVICE_PATH", "/dev/null")
ctx.rule("DEVICE_PATH", "/dev/zero")
ctx.rule("DEVICE_PATH", "/dev/random")
ctx.rule("DEVICE_PATH", "/dev/urandom")
ctx.rule("DEVICE_PATH", "/dev/tty")

ctx.rule("DEVICE_TYPE", "c")  # character device
ctx.rule("DEVICE_TYPE", "b")  # block device

ctx.rule("DEVICE_MAJOR", "1")
ctx.rule("DEVICE_MAJOR", "5")
ctx.rule("DEVICE_MAJOR", "8")

ctx.rule("DEVICE_MINOR", "3")
ctx.rule("DEVICE_MINOR", "5")
ctx.rule("DEVICE_MINOR", "8")
ctx.rule("DEVICE_MINOR", "9")

# Seccomp configuration
ctx.rule("SECCOMP", '"seccomp": \{"defaultAction": "SCMP_ACT_ALLOW"\}')
ctx.rule("SECCOMP", '"seccomp": \{"defaultAction": "SCMP_ACT_ERRNO"\}')
ctx.rule("SECCOMP", '"seccomp": \{"defaultAction": "SCMP_ACT_KILL"\}')

ctx.script(
    "SECCOMP",
    ["SECCOMP_DEFAULT", "SECCOMP_SYSCALLS"],
    lambda default, syscalls: b'"seccomp": {"defaultAction": "%s",%s}' % (default, syscalls),
)

ctx.rule("SECCOMP_DEFAULT", "SCMP_ACT_ALLOW")
ctx.rule("SECCOMP_DEFAULT", "SCMP_ACT_ERRNO")
ctx.rule("SECCOMP_DEFAULT", "SCMP_ACT_KILL")

ctx.script(
    "SECCOMP_SYSCALLS",
    ["SYSCALL_LIST"],
    lambda syscalls: b'"syscalls": [%s]' % syscalls,
)

ctx.script(
    "SYSCALL_LIST",
    ["SYSCALL_ITEM"],
    lambda syscall: syscall,
)

ctx.script(
    "SYSCALL_ITEM",
    ["SYSCALL_NAMES", "SYSCALL_ACTION"],
    lambda names, action: b'{"names": [%s],"action": "%s"}' % (names, action),
)

ctx.rule("SYSCALL_NAMES", '"open","openat"')
ctx.rule("SYSCALL_NAMES", '"write","read"')
ctx.rule("SYSCALL_NAMES", '"mmap","munmap"')
ctx.rule("SYSCALL_NAMES", '"socket","bind","listen"')

ctx.rule("SYSCALL_ACTION", "SCMP_ACT_ALLOW")
ctx.rule("SYSCALL_ACTION", "SCMP_ACT_ERRNO")
ctx.rule("SYSCALL_ACTION", "SCMP_ACT_KILL")

# Sysctl configuration
ctx.rule("SYSCTL", '"sysctl": \{\}')
ctx.script(
    "SYSCTL",
    ["SYSCTL_ITEMS"],
    lambda items: b'"sysctl": {%s}' % items,
)

ctx.rule("SYSCTL_ITEMS", '"net.ipv4.ip_forward": "1"')
ctx.rule("SYSCTL_ITEMS", '"kernel.shm_rmid_forced": "1"')
ctx.rule("SYSCTL_ITEMS", '"net.ipv4.ping_group_range": "0 2147483647"')

# Path security (maskedPaths, readonlyPaths)
ctx.script(
    "PATH_SECURITY",
    ["MASKED_PATHS", "READONLY_PATHS"],
    lambda masked, readonly: b'%s,%s' % (masked, readonly),
)

ctx.rule("PATH_SECURITY", '"maskedPaths": ["/proc/kcore","/proc/latency_stats"]')
ctx.rule("PATH_SECURITY", '"readonlyPaths": ["/proc/sys","/proc/sysrq-trigger"]')

ctx.rule("MASKED_PATHS", '"maskedPaths": []')
ctx.rule("MASKED_PATHS", '"maskedPaths": ["/proc/kcore"]')
ctx.rule("MASKED_PATHS", '"maskedPaths": ["/proc/kcore","/proc/latency_stats","/proc/timer_stats"]')

ctx.rule("READONLY_PATHS", '"readonlyPaths": []')
ctx.rule("READONLY_PATHS", '"readonlyPaths": ["/proc/sys"]')
ctx.rule("READONLY_PATHS", '"readonlyPaths": ["/proc/sys","/proc/sysrq-trigger","/proc/irq","/proc/bus"]')

# Cgroups path
ctx.rule("CGROUPS_PATH", '"cgroupsPath": "/mycontainer"')
ctx.rule("CGROUPS_PATH", '"cgroupsPath": "/docker/containers/123"')
ctx.rule("CGROUPS_PATH", '"cgroupsPath": "/system.slice/myapp.service"')

# ID Mappings (uidMappings, gidMappings)
ctx.script(
    "ID_MAPPINGS",
    ["UID_MAPPINGS", "GID_MAPPINGS"],
    lambda uid, gid: b'%s,%s' % (uid, gid),
)

ctx.rule("ID_MAPPINGS", '"uidMappings": [],"gidMappings": []')

ctx.script(
    "UID_MAPPINGS",
    ["UID_MAPPING_LIST"],
    lambda mappings: b'"uidMappings": [%s]' % mappings,
)

ctx.script(
    "GID_MAPPINGS",
    ["GID_MAPPING_LIST"],
    lambda mappings: b'"gidMappings": [%s]' % mappings,
)

ctx.script(
    "UID_MAPPING_LIST",
    ["ID_MAPPING_ITEM"],
    lambda mapping: mapping,
)

ctx.script(
    "GID_MAPPING_LIST",
    ["ID_MAPPING_ITEM"],
    lambda mapping: mapping,
)

ctx.script(
    "ID_MAPPING_ITEM",
    ["CONTAINER_ID", "HOST_ID", "SIZE_VAL"],
    lambda cid, hid, size: b'{"containerID": %s,"hostID": %s,"size": %s}' % (cid, hid, size),
)

ctx.rule("CONTAINER_ID", "0")
ctx.rule("CONTAINER_ID", "1000")
ctx.rule("HOST_ID", "1000")
ctx.rule("HOST_ID", "100000")
ctx.rule("SIZE_VAL", "65536")
ctx.rule("SIZE_VAL", "1")

# Rootfs propagation
ctx.rule("ROOTFS_PROPAGATION", '"rootfsPropagation": "private"')
ctx.rule("ROOTFS_PROPAGATION", '"rootfsPropagation": "rprivate"')
ctx.rule("ROOTFS_PROPAGATION", '"rootfsPropagation": "shared"')
ctx.rule("ROOTFS_PROPAGATION", '"rootfsPropagation": "rshared"')
ctx.rule("ROOTFS_PROPAGATION", '"rootfsPropagation": "slave"')
ctx.rule("ROOTFS_PROPAGATION", '"rootfsPropagation": "rslave"')

# =============================================================================
# MOUNTS AND ANNOTATIONS (from original)
# =============================================================================

# Mounts (optional)
ctx.rule("MOUNTS", '"mounts": []')
ctx.script("MOUNTS", ["MOUNT_ITEM"], lambda mount: b'"mounts": [%s]' % mount)

ctx.script(
    "MOUNT_ITEM",
    ["MOUNT_DEST", "MOUNT_TYPE", "MOUNT_SRC"],
    lambda dest, type, src: b'{"destination": "%s","type": "%s","source": "%s"}'
    % (dest, type, src),
)

ctx.rule("MOUNT_DEST", "/proc")
ctx.rule("MOUNT_DEST", "/tmp")
ctx.rule("MOUNT_DEST", "/dev/shm")
ctx.rule("MOUNT_DEST", "/sys")

ctx.rule("MOUNT_TYPE", "proc")
ctx.rule("MOUNT_TYPE", "tmpfs")
ctx.rule("MOUNT_TYPE", "sysfs")
ctx.rule("MOUNT_TYPE", "bind")

ctx.rule("MOUNT_SRC", "proc")
ctx.rule("MOUNT_SRC", "tmpfs")
ctx.rule("MOUNT_SRC", "sysfs")
ctx.rule("MOUNT_SRC", "/host/path")

# Annotations (optional)
ctx.rule("ANNOTATIONS", '"annotations": \{\}')
ctx.script(
    "ANNOTATIONS",
    ["ANNOTATION_ITEM"],
    lambda annotation: b'"annotations": {%s}' % annotation,
)

ctx.script(
    "ANNOTATION_ITEM",
    ["ANNOTATION_KEY", "ANNOTATION_VALUE"],
    lambda key, value: b'"%s": "%s"' % (key, value),
)

ctx.rule("ANNOTATION_KEY", "com.example.key1")
ctx.rule("ANNOTATION_KEY", "com.example.key2")
ctx.rule("ANNOTATION_KEY", "org.opencontainers.image.created")
ctx.rule("ANNOTATION_KEY", "org.opencontainers.image.authors")

ctx.rule("ANNOTATION_VALUE", "value1")
ctx.rule("ANNOTATION_VALUE", "value2")
ctx.rule("ANNOTATION_VALUE", "2024-01-01T00:00:00Z")
ctx.rule("ANNOTATION_VALUE", "example@example.com")
