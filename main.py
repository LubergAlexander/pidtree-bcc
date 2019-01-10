import sys
import argparse
from bcc import BPF
import json
import yaml
import psutil
import os
import socket
import struct
from jinja2 import Template

bpf_text = """
#include <net/sock.h>
#include <bcc/proto.h>

#define first_n_bits(n, ip) (ip<<(32 - n))>>(32 - n)
{% for mask in masks %}
// {{ mask.get("description", mask["subnet_name"]) }}
#define subnet_{{ mask["subnet_name"] }} {{ binary_encode(mask["network"], mask["network_mask_length"]) }}
#define subnet_{{ mask["subnet_name"] }}_length {{ mask["network_mask_length"] }}
{% endfor %}

BPF_HASH(currsock, u32, struct sock *);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
    u32 pid = bpf_get_current_pid_tgid();
    currsock.update(&pid, &sk);
    return 0;
};

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();

    struct sock **skpp;
    skpp = currsock.lookup(&pid);
    if (skpp == 0) return 0; // not there!
    if (ret != 0) {
        // failed to sync
        currsock.delete(&pid);
        return 0;
    }
    
    struct sock *skp = *skpp;
    u32 saddr = 0, daddr = 0;
    u16 dport = 0;
    bpf_probe_read(&daddr, sizeof(daddr), &skp->__sk_common.skc_daddr);
    {% for length in mask_lengths %}
    u32 first_{{ length }}_bits = first_n_bits({{ length }}, daddr);
    {% endfor %}
    if (0 // for easier templating {% for mask in masks %}
         || (u32) first_{{ mask["network_mask_length"] }}_bits == (u32) subnet_{{ mask["subnet_name"] }}
    {% endfor %}) {
        currsock.delete(&pid);
        return 0;
    }

    bpf_probe_read(&saddr, sizeof(saddr), &skp->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);

    bpf_trace_printk("{\\"pid\\": %d, \\"daddr\\": \\"%x\\", \\"dport\\": %d}\\n",
                     pid, daddr, ntohs(dport));
    
    currsock.delete(&pid);

    return 0;
}
"""

def parse_args():
    """ Parses args """
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", type=str, help="yaml file containing subnet safelist information")
    parser.add_argument("-p", "--print-and-quit", action='store_true', default=False, help="don't run, just print the eBPF program to be compiled and quit")
    args = parser.parse_args()
    if args.config is not None and not os.path.exists(args.config):
        os.stderr.write("--config file does not exist")
    return(args)

def parse_config(config_file):
    """ Parses yaml file at path `config_file` """
    if config_file is None:
        return {}
    return yaml.load(open(config_file, 'r').read())

def binary_encode(network, mask_length):
    """ Takes an IP and a mask and returns the binary encoding of the masked bits """
    binary_encode = ""
    inverse_mask_length = 32 - int(mask_length)
    network = (struct.unpack('!L', socket.inet_aton(network))[0] >> inverse_mask_length) << inverse_mask_length
    for j in range(0,4):
        for i in range(0,8):
            print i + j
            if network & 1 << (i + (j * 8)):
                binary_encode = binary_encode + "1"
            else:
                binary_encode = binary_encode + "0"
    return "0b{}".format(binary_encode)
    
def crawl_process_tree(proc):
    """ Takes a process and returns all process ancestry until the ppid is 0 """
    procs = [proc]
    while True:
        ppid = procs[len(procs)-1].ppid()
        if ppid == 0:
            break
        procs.append(psutil.Process(ppid))
    return procs
    
def main(args):
    config = parse_config(args.config)
    global bpf_text
    all_mask_lengths = []
    if config.get("masks") is not None:
        all_mask_lengths = set([mask["network_mask_length"] for mask in config["masks"]])
    expanded_bpf_text = Template(bpf_text).render(
        binary_encode=binary_encode,
        masks=config.get("masks", []),
        mask_lengths=all_mask_lengths
    )
    if args.print_and_quit:
        print(expanded_bpf_text)
        sys.exit(0)
    b = BPF(text=expanded_bpf_text)
    while True:
        trace = b.trace_readline()
        print(trace)
        # FIXME: this next line isn't right - sometimes there are more colons
        json_event = trace.split(":", 2)[2:][0]
        event = json.loads(json_event)
        proc = None
        proctree = []
        error = ""
        try:
            proc = psutil.Process(event["pid"])
            proctree = crawl_process_tree(proc)
        except Exception as e:
            error=str(e)
        print(json.dumps(
            {"pid": event["pid"],
             "proctree": list(((p.pid, " ".join(p.cmdline()), p.username()) for p in proctree)),
             "daddr": socket.inet_ntoa(struct.pack('<L', int(event["daddr"], 16))),
             "port": event["dport"],
             "error": error}))
    sys.exit(0)

if __name__ == "__main__":
    main(parse_args())
