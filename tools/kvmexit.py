#!/usr/bin/env python
#
# kvmexit.py
#
# Display the exit_reason and its statistics of each kvm_exit
# for all vcpus of all virtual machines. For example,
# $./kvmexit.py
#  TGID     PID      KVM_EXIT_REASON                     STAT
#  1273551  1273568  EXIT_REASON_MSR_WRITE               6
#  1274253  1274261  EXIT_REASON_EXTERNAL_INTERRUPT      1
#  1274253  1274261  EXIT_REASON_HLT                     12
#  ...
#
# @TGID: each vitual machine's pid in the user space.
# @PID: the user space's thread of each vcpu of that virtual machine.
# @KVM_EXIT_REASON: the reason why the vm exits.
# @STAT: the counts of the @KVM_EXIT_REASON since the vm starts, and
#        it is recorded every second by setting `sleep(1)`.
#
# REQUIRES: Linux 4.7+ (BPF_PROG_TYPE_TRACEPOINT support)
#
# Copyright (c) 2019 BYTEDANCE Inc.
#
# Author(s):
#   Fei Li <lifei.shirley@bytedance.com>


from __future__ import print_function
from time import sleep, strftime
from bcc import BPF
import argparse
import multiprocessing
import signal
import subprocess

#
# Process Arguments
#

# arg validation
def positive_int(val):
    try:
        ival = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if ival < 0:
        raise argparse.ArgumentTypeError("must be positive")
    return ival

def positive_nonzero_int(val):
    ival = positive_int(val)
    if ival == 0:
        raise argparse.ArgumentTypeError("must be nonzero")
    return ival

# arguments
examples = """examples:
    ./kvmexit             # Display kvm_exit_reason and its statistics until Ctrl-C
    ./kvmexit 5           # Display kvm_exit_reason and its statistics for 5 seconds only
"""
parser = argparse.ArgumentParser(
    description="Display kvm_exit_reason and its statistics at a timed interval",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("duration", nargs="?", default=99999999,
    type=positive_nonzero_int,
    help="duration of trace, in seconds")

args = parser.parse_args()
duration = int(args.duration)

#
# Setup BPF
#

# load BPF program
bpf_text = """
#include <linux/delay.h>

#define REASON_NUM 69
#define TGID_NUM 1024

struct exit_count {
    u64 exit_ct[REASON_NUM];
};
BPF_PERCPU_ARRAY(init_value, struct exit_count, 1);
BPF_TABLE("percpu_hash", u64, struct exit_count, pcpu_kvm_stat, TGID_NUM);

struct cache_info {
    u64 cache_pid_tgid;
    struct exit_count cache_exit_ct;
};
BPF_PERCPU_ARRAY(pcpu_cache, struct cache_info, 1);

FUNC_ENTRY {
    u64 cur_pid_tgid = bpf_get_current_pid_tgid();
    int zero = 0;
    int cache_miss = 0;
    u32 er = GET_ER;
    if (er >= REASON_NUM) {
        return -1;
    }

    struct exit_count *tmp_info, *initial;
    struct cache_info *cache_p;
    cache_p = pcpu_cache.lookup(&zero);
    if (cache_p != NULL) {
        if (cache_p->cache_pid_tgid == cur_pid_tgid) {
            //a. If the cur_pid_tgid hit this physical cpu consecutively, save it to pcpu_cache
            tmp_info = &cache_p->cache_exit_ct;
        } else {
            //b. If another pid_tgid matches this pcpu for the last hit, OR it is the first time to hit this physical cpu.
            cache_miss = 1;
        }
    } else {
        return -1;
    }

    if (tmp_info == NULL) {
        // b.a Try to load the last cache struct if existed.
        tmp_info = pcpu_kvm_stat.lookup(&cur_pid_tgid);
    }
    if (tmp_info == NULL) {
        // b.b If it is the first time for the cur_pid_tgid to hit this pcpu, employ a per_cpu array to initialize pcpu_kvm_stat's exit_count with each exit reason's count is zero
        initial = init_value.lookup(&zero);
        if (initial != NULL) {
            pcpu_kvm_stat.update(&cur_pid_tgid, initial);
            tmp_info = pcpu_kvm_stat.lookup(&cur_pid_tgid);
            // To pass the verifier
            if (tmp_info == NULL) {
                return -1;
            }
        } else {
            return -1;
        }
    }

    if (er < REASON_NUM) {
        tmp_info->exit_ct[er]++;
        if (cache_miss == 1) {
            if (cache_p->cache_pid_tgid != 0) {
                // b.*.a Let's save the last hit cache_info into kvm_stat.
                pcpu_kvm_stat.update(&cache_p->cache_pid_tgid, &cache_p->cache_exit_ct);
            }
            // b.* save to pcpu_cache
            cache_p->cache_pid_tgid = cur_pid_tgid;
            bpf_probe_read(&cache_p->cache_exit_ct, sizeof(*tmp_info), tmp_info);
        }
        return 0;
    }

    return -1;
}
"""

# format output
exit_reasons = (
    "EXIT_REASON_EXCEPTION_NMI",
    "EXIT_REASON_EXTERNAL_INTERRUPT",
    "EXIT_REASON_TRIPLE_FAULT",
    "EXIT_REASON_INIT_SIGNAL",
    "",
    "",
    "",
    "EXIT_REASON_PENDING_INTERRUPT",
    "EXIT_REASON_NMI_WINDOW",
    "EXIT_REASON_TASK_SWITCH",
    "EXIT_REASON_CPUID",
    "",
    "EXIT_REASON_HLT",
    "EXIT_REASON_INVD",
    "EXIT_REASON_INVLPG",
    "EXIT_REASON_RDPMC",
    "EXIT_REASON_RDTSC",
    "",
    "EXIT_REASON_VMCALL",
    "EXIT_REASON_VMCLEAR",
    "EXIT_REASON_VMLAUNCH",
    "EXIT_REASON_VMPTRLD",
    "EXIT_REASON_VMPTRST",
    "EXIT_REASON_VMREAD",
    "EXIT_REASON_VMRESUME",
    "EXIT_REASON_VMWRITE",
    "EXIT_REASON_VMOFF",
    "EXIT_REASON_VMON",
    "EXIT_REASON_CR_ACCESS",
    "EXIT_REASON_DR_ACCESS",
    "EXIT_REASON_IO_INSTRUCTION",
    "EXIT_REASON_MSR_READ",
    "EXIT_REASON_MSR_WRITE",
    "EXIT_REASON_INVALID_STATE",
    "EXIT_REASON_MSR_LOAD_FAIL",
    "",
    "EXIT_REASON_MWAIT_INSTRUCTION",
    "EXIT_REASON_MONITOR_TRAP_FLAG",
    "",
    "EXIT_REASON_MONITOR_INSTRUCTION",
    "EXIT_REASON_PAUSE_INSTRUCTION",
    "EXIT_REASON_MCE_DURING_VMENTRY",
    "",
    "EXIT_REASON_TPR_BELOW_THRESHOLD",
    "EXIT_REASON_APIC_ACCESS",
    "EXIT_REASON_EOI_INDUCED",
    "EXIT_REASON_GDTR_IDTR",
    "EXIT_REASON_LDTR_TR",
    "EXIT_REASON_EPT_VIOLATION",
    "EXIT_REASON_EPT_MISCONFIG",
    "EXIT_REASON_INVEPT",
    "EXIT_REASON_RDTSCP",
    "EXIT_REASON_PREEMPTION_TIMER",
    "EXIT_REASON_INVVPID",
    "EXIT_REASON_WBINVD",
    "EXIT_REASON_XSETBV",
    "EXIT_REASON_APIC_WRITE",
    "EXIT_REASON_RDRAND",
    "EXIT_REASON_INVPCID",
    "EXIT_REASON_VMFUNC",
    "EXIT_REASON_ENCLS",
    "EXIT_REASON_RDSEED",
    "EXIT_REASON_PML_FULL",
    "EXIT_REASON_XSAVES",
    "EXIT_REASON_XRSTORS",
    "",
    "",
    "EXIT_REASON_UMWAIT",
    "EXIT_REASON_TPAUSE"
)

try:
    has_kvm = subprocess.check_output("lsmod | grep kvm", shell=True)
except Exception as e:
    raise Exception("Please insmod kvm module to use kvmexit")

try:
    uname = subprocess.check_output("uname -r", shell=True).split('.')[:2]
    if int(uname[0]) >= 5:
        func_entry = "RAW_TRACEPOINT_PROBE(kvm_exit)"
        get_er = "ctx->args[0]"
    elif uname[0] == "4":
        if int(uname[1]) >= 7:
            func_entry = "TRACEPOINT_PROBE(kvm, kvm_exit)"
            get_er = "args->exit_reason"
        else:
            raise Exception("Kernel version < 4.7 is not supported")
    else:
        raise Exception("Only kernel version >= 4.7 is supported")
except Exception as e:
    raise Exception("Failed to run kvmexit due to: %s" % e)


# For kernel >= 5.0, use RAW_TRACEPOINT for performance consideration
bpf_text = bpf_text.replace('FUNC_ENTRY', func_entry)
bpf_text = bpf_text.replace('GET_ER', get_er)
b = BPF(text=bpf_text)


# header
print("Display kvm exit reasons and statistics", end="")
if duration < 99999999:
    print(" for %d secs." % duration)
else:
    print("... Hit Ctrl-C to end.")
print("%-8s %-8s %-35s %s" % ("TGID", "PID", "KVM_EXIT_REASON", "STAT"))

# signal handler
def signal_ignore(signal, frame):
        print()
try:
    sleep(duration)
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, signal_ignore)

# output
pcpu_kvm_stat = b["pcpu_kvm_stat"]
pcpu_cache = b["pcpu_cache"]
EXIT_REASON_NUM = 69
for k, v in pcpu_kvm_stat.items():
    tgid = k.value >> 32
    pid = k.value & 0xffffffff
    for i in range(0, EXIT_REASON_NUM):
        sum1 = 0
        for inner_cpu in range(0, multiprocessing.cpu_count()):
            cachePIDTGID = pcpu_cache[0][inner_cpu].cache_pid_tgid
            # Take priority to check if it is in cache
            if cachePIDTGID == k.value:
                sum1 += pcpu_cache[0][inner_cpu].cache_exit_ct.exit_ct[i]
            # If not in cache, find from kvm_stat
            else:
                sum1 += v[inner_cpu].exit_ct[i]
        if sum1 == 0:
            continue
        print("%-8u %-8u %-35s %-8u" % (tgid, pid, exit_reasons[i], sum1))
