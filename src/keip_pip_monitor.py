"""
KEIP Pip Monitor - Kernel-Enforced Install-Time Policies
Behavioral Detection System
"""

import sys
import os
import socket
import struct
import time
import signal
import json
import argparse
from bcc import BPF

__version__ = "1.0.0"
__author__ = "Otsmane Ahmed"
__github__ = "https://github.com/Otsmane-Ahmed/KEIP"

QUIET = False


def print_banner():
    """Display KEIP banner with credits."""
    if not QUIET:
        print("""
╔═════════════════════════════════════════════════════════╗
║  KEIP v1.0.0 - Kernel-Enforced Install-Time Policies    ║
║  eBPF-based Python Package Security Monitor             ║
║                                                         ║
║  Author: Otsmane Ahmed                                  ║
║  GitHub: https://github.com/Otsmane-Ahmed/KEIP          ║
╚═════════════════════════════════════════════════════════╝
        """)


def log(message):
    """Print message unless in quiet mode."""
    if not QUIET:
        print(message)


def load_config():
    """Load behavioral detection configuration from config.json."""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    defaults = {
        "behavioral_detection": {
            "allowed_ports": [80, 443, 53],
            "max_unique_ips": 5,
            "max_send_bytes": 20480,
            "send_receive_ratio": 0.1
        },
        "monitoring": {
            "process_names": ["pip", "pip3", "python", "python3"]
        }
    }
    
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            log(f"[*] Loaded configuration from {config_path}")
            return config
    except FileNotFoundError:
        log("[!] config.json not found - using defaults")
        return defaults
    except json.JSONDecodeError:
        log("[!] config.json is invalid - using defaults")
        return defaults


bpf_text = """
#include <linux/security.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/errno.h>
#include <linux/binfmts.h>
#include <linux/sched.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>

#ifndef EPERM
#define EPERM 1
#endif

// Map to track PIDs running pip/python
BPF_HASH(monitored_pids, u32, u32);

// Map to track unique IP connections per PID
struct ip_key {
    u32 pid;
    u32 ip;
};
BPF_HASH(ip_tracker, struct ip_key, u32);

// Map to count unique IPs per PID
BPF_HASH(ip_count, u32, u32);

// Map to track traffic bytes per PID
struct traffic_data {
    u64 bytes_sent;
    u64 bytes_received;
};
BPF_HASH(byte_tracker, u32, struct traffic_data);

// Event structure for logging
struct event_t {
    u32 pid;
    u32 dest_ip;
    u16 dest_port;
    u8 blocked;
    u8 reason;  // 1=port, 2=ip_count, 3=exfiltration
};
BPF_PERF_OUTPUT(events);

LSM_PROBE(bprm_check_security, struct linux_binprm *bprm) {
    char filename[128];
    bpf_probe_read_str(filename, sizeof(filename), bprm->filename);

    // Inherit monitoring status from parent
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task;
    u32 parent_pid;

    bpf_probe_read(&parent_task, sizeof(parent_task), &task->real_parent);
    bpf_probe_read(&parent_pid, sizeof(parent_pid), &parent_task->tgid);

    u32 *parent_monitored = monitored_pids.lookup(&parent_pid);

    if (parent_monitored) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u32 val = 1;
        monitored_pids.update(&pid, &val);
    }
    
    // Check for pip, pip3, python, python3 in filename
    int found = 0;
    
    #pragma unroll
    for (int i = 0; i < 100; i++) {
        if (filename[i] == 0) break;
        
        // Check for "pip" or "pip3"
        if (filename[i] == 'p' && filename[i+1] == 'i' && filename[i+2] == 'p') {
            found = 1;
            break;
        }
        
        // Check for "python" or "python3"
        if (filename[i] == 'p' && filename[i+1] == 'y' && filename[i+2] == 't' && 
            filename[i+3] == 'h' && filename[i+4] == 'o' && filename[i+5] == 'n') {
            found = 1;
            break;
        }
    }
    
    if (found) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u32 val = 1;
        monitored_pids.update(&pid, &val);
    }
    
    return 0;
}

LSM_PROBE(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Only monitor tracked PIDs
    u32 *is_monitored = monitored_pids.lookup(&pid);
    if (!is_monitored) {
        return 0;
    }
    
    // Handle IPv4 and IPv6
    u32 dest_ip = 0;
    u16 dest_port = 0;
    
    if (address->sa_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
        dest_ip = addr_in->sin_addr.s_addr;
        dest_port = bpf_ntohs(addr_in->sin_port);
    } else if (address->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)address;
        dest_port = bpf_ntohs(addr_in6->sin6_port);
        // For IPv6, we only check port (simplified for now)
    } else {
        return 0;  // Unknown address family, allow
    }
    
    // RULE 0: Always allow localhost (127.0.0.0/8 and 0.0.0.0)
    if (address->sa_family == AF_INET) {
        u8 first_octet = dest_ip & 0xFF;
        if (dest_ip == 0 || first_octet == 127) {
            return 0;  // Allow localhost
        }
    }
    
    // RULE 1: Port Trap - Only allow 80, 443, 53
    if (dest_port != 80 && dest_port != 443 && dest_port != 53) {
        struct event_t event = {};
        event.pid = pid;
        event.dest_ip = dest_ip;
        event.dest_port = dest_port;
        event.blocked = 1;
        event.reason = 1;  // Port violation
        events.perf_submit(ctx, &event, sizeof(event));
        return -EPERM;
    }
    
    // RULE 2: Connection Counter - Max 5 unique IPs
    if (address->sa_family == AF_INET && dest_port != 53) {  // Don't count DNS
        struct ip_key key = {};
        key.pid = pid;
        key.ip = dest_ip;
        
        u32 *exists = ip_tracker.lookup(&key);
        if (!exists) {
            // New IP for this PID
            u32 val = 1;
            ip_tracker.update(&key, &val);
            
            // Increment count
            u32 *count = ip_count.lookup(&pid);
            u32 new_count = 1;
            if (count) {
                new_count = *count + 1;
            }
            ip_count.update(&pid, &new_count);
            
            // Check threshold
            if (new_count > 5) {
                struct event_t event = {};
                event.pid = pid;
                event.dest_ip = dest_ip;
                event.dest_port = dest_port;
                event.blocked = 1;
                event.reason = 2;  // Too many IPs
                events.perf_submit(ctx, &event, sizeof(event));
                return -EPERM;
            }
        }
    }
    
    // Allow connection (passes all checks)
    struct event_t event = {};
    event.pid = pid;
    event.dest_ip = dest_ip;
    event.dest_port = dest_port;
    event.blocked = 0;
    event.reason = 0;
    events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// Cleanup when process exits
TRACEPOINT_PROBE(sched, sched_process_exit) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Clean up all maps
    monitored_pids.delete(&pid);
    ip_count.delete(&pid);
    byte_tracker.delete(&pid);
    
    // Note: ip_tracker entries are harder to clean without iteration
    // They will be naturally limited by map size and overwritten
    
    return 0;
}
"""


def ip_to_int(ip_str):
    """Convert IP string to 32-bit integer (network byte order)."""
    return struct.unpack("I", socket.inet_aton(ip_str))[0]

def int_to_ip(ip_int):
    """Convert 32-bit integer to IP string."""
    return socket.inet_ntoa(struct.pack("I", ip_int))



def main():
    print_banner()
    log("[*] KEIP Monitor Starting...")
    log("[*] Behavioral Detection Mode Enabled")
    
    config = load_config()
    behavior = config.get("behavioral_detection", {})
    monitoring = config.get("monitoring", {})
    
    allowed_ports = behavior.get("allowed_ports", [80, 443, 53])
    max_ips = behavior.get("max_unique_ips", 5)
    
    log(f"[*] Configuration:")
    log(f"    - Allowed ports: {allowed_ports}")
    log(f"    - Max unique IPs: {max_ips}")
    log(f"    - Monitoring: {', '.join(monitoring.get('process_names', []))}")
    
    log("[*] Compiling eBPF program...")
    try:
        b = BPF(text=bpf_text)
    except Exception as e:
        print(f"[-] Compilation failed: {e}")
        sys.exit(1)
    log("[+] eBPF program compiled")
    
    hooks_attached = 0
    
    try:
        b.attach_lsm(fn_name="bprm_check_security")
        log("[+] bprm_check_security attached")
        hooks_attached += 1
    except Exception as e:
        if "attached" in str(e).lower():
            log("[!] bprm_check_security already attached (continuing...)")
        else:
            print(f"[-] Failed to attach bprm_check_security: {e}")
            sys.exit(1)
    
    try:
        b.attach_lsm(fn_name="socket_connect")
        log("[+] socket_connect attached")
        hooks_attached += 1
    except Exception as e:
        if "attached" in str(e).lower():
            log("[!] socket_connect already attached (continuing...)")
        else:
            print(f"[-] Failed to attach socket_connect: {e}")
            sys.exit(1)
    
    log(f"[+] LSM hooks ready ({hooks_attached} newly attached)")
    
    # Map reason codes to descriptions
    BLOCK_REASONS = {
        1: "Suspicious port (not 80/443/53)",
        2: "Too many unique IPs (>5)",
        3: "Data exfiltration detected"
    }
    
    def print_event(cpu, data, size):
        event = b["events"].event(data)
        ip_str = int_to_ip(event.dest_ip) if event.dest_ip else "unknown"
        color = "\033[91m" if event.blocked else "\033[92m"
        reset = "\033[0m"
        
        if event.blocked:
            reason = BLOCK_REASONS.get(event.reason, "Unknown reason")
            print(f"{color}[BLOCKED]{reset} PID {event.pid} -> {ip_str}:{event.dest_port}")
            print(f"  {color}Reason: {reason}{reset}")
            try:
                pgid = os.getpgid(event.pid)
                print(f"  {color}[!] Terminating process group {pgid}...{reset}")
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception as e:
                print(f"  [!] Kill failed: {e}")
        else:
            print(f"{color}[ALLOWED]{reset} PID {event.pid} -> {ip_str}:{event.dest_port}")

    b["events"].open_perf_buffer(print_event)
    
    log("[*] Monitoring active. Press Ctrl+C to stop.")
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="KEIP - Kernel-Enforced Install-Time Policies Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress informational messages (only show blocks/allows)'
    )
    args = parser.parse_args()
    
    if args.quiet:
        QUIET = True
    
    if os.geteuid() != 0:
        print("[-] This script requires root privileges")
        print("    Run with: sudo python3 keip_pip_monitor.py")
        sys.exit(1)
    
    main()
