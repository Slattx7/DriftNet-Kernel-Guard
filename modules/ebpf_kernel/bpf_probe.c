//go:build ignore
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 256

struct data_t {
    __u32 pid;
    __u32 uid;
    char comm[16];
    char fname[MAX_PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
} blacklist_pids SEC(".maps");

/*
 DISABLED: Hooking sys_openat causes Fatal Kernel Panics on CRDroid due to high
 frequency event lock contention.
*/

struct sockaddr_in_v4 {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
};

struct sockaddr_in_v6 {
    unsigned short sin6_family;
    unsigned short sin6_port;
    unsigned int sin6_flowinfo;
    unsigned char sin6_addr[16];
    unsigned int sin6_scope_id;
};

SEC("kprobe/security_socket_connect")
int bpf_prog_connect(struct pt_regs *ctx)
{
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Ring-0 Atomic Active Mitigation: instant kernel kill for blacklisted PIDs
    __u32 *is_blocked = bpf_map_lookup_elem(&blacklist_pids, &data.pid);
    if (is_blocked) {
        bpf_send_signal(9); // SIGKILL immediately at Ring-0
        return 0;
    }

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    void *address = (void *)PT_REGS_PARM2(ctx);
    unsigned short family = 0;
    bpf_probe_read(&family, sizeof(family), address);

    if (family == 2) { // AF_INET (IPv4)
        struct sockaddr_in_v4 addr = {};
        bpf_probe_read(&addr, sizeof(addr), address);

        unsigned int ip = addr.sin_addr;
        unsigned short port = ((addr.sin_port & 0xFF) << 8) | ((addr.sin_port >> 8) & 0xFF);

        data.fname[0] = 'I'; data.fname[1] = 'P'; data.fname[2] = ':';
        data.fname[3] = ip & 0xFF;
        data.fname[4] = (ip >> 8) & 0xFF;
        data.fname[5] = (ip >> 16) & 0xFF;
        data.fname[6] = (ip >> 24) & 0xFF;
        data.fname[7] = port >> 8;
        data.fname[8] = port & 0xFF;
        data.fname[9] = 0;
    } else if (family == 10) { // AF_INET6 (IPv6)
        struct sockaddr_in_v6 addr6 = {};
        bpf_probe_read(&addr6, sizeof(addr6), address);

        unsigned short port = ((addr6.sin6_port & 0xFF) << 8) | ((addr6.sin6_port >> 8) & 0xFF);

        data.fname[0] = 'I'; data.fname[1] = 'P'; data.fname[2] = '6'; data.fname[3] = ':';
        #pragma unroll
        for (int i = 0; i < 16; i++) {
            data.fname[4 + i] = addr6.sin6_addr[i];
        }
        data.fname[20] = port >> 8;
        data.fname[21] = port & 0xFF;
        data.fname[22] = 0;
    } else {
        return 0; // Filter non-IP sockets
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/do_execve_file")
int bpf_prog_execve(struct pt_regs *ctx)
{
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Ring-0 Atomic Active Mitigation: instant kernel kill for blacklisted PIDs
    __u32 *is_blocked = bpf_map_lookup_elem(&blacklist_pids, &data.pid);
    if (is_blocked) {
        bpf_send_signal(9); // SIGKILL immediately at Ring-0
        return 0;
    }

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    void *filename_struct = (void *)PT_REGS_PARM2(ctx);
    char *fname_ptr;
    bpf_probe_read(&fname_ptr, sizeof(fname_ptr), filename_struct);

    data.fname[0] = 'E'; data.fname[1] = 'X'; data.fname[2] = 'E'; data.fname[3] = 'C'; data.fname[4] = ':';
    bpf_probe_read_str(&data.fname[5], sizeof(data.fname) - 5, fname_ptr);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char _license[] SEC("license") = "GPL";
