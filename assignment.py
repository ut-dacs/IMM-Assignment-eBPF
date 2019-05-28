#!/usr/bin/python
#   Forked from xdp_drop_count.py
#
#   Exercise:   
#   Count the number of packets for each ingoing flows with eBPF
#   Develop a program that categorizes, counts and displays ingoing flows
#   using BCC (BPF Compiler Collection) and Python 2.7
#
#   Current state of this code:
#   The programs count the number of packetd for each pair srcip-dstip
#   Exercise to complete:
#   Extend the following code in order to count the packet for each ingoing flows   
#
#   First run:
#   sudo python exercise.py docker0
#   Then run in another terminal the test set:
#   docker run -it r4ffy/flows:latest //generate flows
#   
#   You should expect this simple output after a while:
#   Printing Flows, hit CTRL+C to stop
#         srcip         dstip srcport dstport proto counter
#   172.17.0.2  10.100.100.3      20       1   tcp       1
#   172.17.0.2  10.100.100.3      20       2   tcp       1
#   172.17.0.2  10.100.100.3      20       3   tcp       1
#   172.17.0.2  10.100.100.3      20       4   tcp       1
#   172.17.0.2  10.100.100.3      20       5   tcp       1
#   172.17.0.2  10.100.100.1      20       1   tcp       2
#   172.17.0.2  10.100.100.1      20       2   tcp       2
#   172.17.0.2  10.100.100.1      20       3   tcp       2
#   172.17.0.2  10.100.100.1      20       4   tcp       2
#   172.17.0.2  10.100.100.2      20       1   tcp       2
#   172.17.0.2  10.100.100.2      20       2   tcp       2
#   172.17.0.2  10.100.100.2      20       3   tcp       2
#   172.17.0.2  10.100.100.2      20       4   tcp       2
#   172.17.0.2  10.100.100.2      20       5   tcp       2
#   172.17.0.2  10.100.100.1      20       5   tcp       5


from bcc import BPF #general BCC libray for python
import time
import sys
import socket
import struct
import os
import pandas as pd

flags = 0


def usage():
    print("Usage: {0} <ifdev>".format(sys.argv[0]))
    print("e.g.: {0} eth0\n".format(sys.argv[0]))
    exit(1)


if len(sys.argv) < 2 or len(sys.argv) > 2:
    usage()

if len(sys.argv) == 2:
    device = sys.argv[1]

mode = BPF.XDP
ret = "XDP_PASS"
ctxtype = "xdp_md"

# load BPF program
b = BPF(text="""
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
struct flow {
    u32 src_ip;
    u32 dst_ip;
    
    /* extend this struct */
    
};
// Flow Map with counter
BPF_HASH(flowmap, struct flow, u64);


int xdp_prog1(struct CTXTYPE *ctx) {
    void* data_end = (void*)(long)ctx->data_end;  //extract the pointer to the end  of the ethernet frame (used for safety check)
    void* data = (void*)(long)ctx->data; //extract the ethernet frame
    struct ethhdr *eth = data; //cast to ethernet header
    int rc = RETURNCODE;
    uint16_t h_proto; //h_proto is used for store the ethertype
    uint64_t nh_off = 0; //nh_off is used for store Ethernet Header lenght
    nh_off = sizeof(*eth); // Ethernet Header is equal to sizeof ethernet header structure
    if (data + nh_off  > data_end) //  First safety check if the pointer to the start of the packet plus the ethernet header length
        return rc;                 //  is greater than the end of packet (malformed ethernet frame) the program ends.
    h_proto = eth->h_proto; // ethertype is ethhdr struct https://elixir.bootlin.com/linux/v5.2-rc1/source/include/uapi/linux/if_ether.h#L162
    // parse double layer vlans
    #pragma unroll
    for (int i=0; i<2; i++) {
        if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {  // if ethertype is 802.1Q
            struct vlan_hdr *vhdr;
            vhdr = data + nh_off; //extract vlan header
            nh_off += sizeof(struct vlan_hdr); //increment Ethernet Header offset of vlan header
            if (data + nh_off > data_end) //safety check again!
                return rc;
            h_proto = vhdr->h_vlan_encapsulated_proto; //set hproto to encapsulated protocol.
        }
    }
    if (h_proto == htons(ETH_P_IP)){ //If protocol is IP
        struct iphdr *iph = data + nh_off; //Move the data pointer to the ip header and cast to iphdr https://elixir.bootlin.com/linux/v5.2-rc1/source/include/uapi/linux/ip.h#L86
        if (iph+1 > data_end){ //Safety check! now we are operating with struct iphdr pointer type 
            return 0;          //in C: iph+1 means data + nh_off + sizeof(struct iphdr). 
        }
        u32 dst_ip = ntohl(iph->daddr); //network to host byte order
        u32 src_ip = ntohl(iph->saddr);
        // https://elixir.bootlin.com/linux/v5.2-rc1/source/include/uapi/linux/udp.h#L23
	// https://elixir.bootlin.com/linux/v5.2-rc1/source/include/uapi/linux/tcp.h#L25
        /* ADD your code here */
        
        struct flow my_flow = {}; //inizialize the struct
        my_flow.src_ip=src_ip;	//fill the fields
        my_flow.dst_ip=dst_ip;
        
        /* ADD your code here */
        
        u64 zero = 0, *val; //Zero is the init value, must be passed by address
        val = flowmap.lookup_or_init(&my_flow,&zero); // get or init element in the table
        if (val) //if the pointer exist => != 0 => !=NULLPTR
            *val += 1; // dereference and increment value
    }
    return rc;  
}
""", cflags=["-w", "-DRETURNCODE=%s" % ret, "-DCTXTYPE=%s" % ctxtype])

# Convert binary in dotted decimal notation.
def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

# Get reference to C function
fn = b.load_func("xdp_prog1", mode)

# Attach to the network interface
if mode == BPF.XDP:
    b.attach_xdp(device, fn, flags)

#Get reference to C HashMap
flowmap = b.get_table("flowmap")
print("Starting")
while 1:
    try:
        os.system('clear')
        print("Printing Flows, hit CTRL+C to stop")
        df = pd.DataFrame(columns=['srcip', 'dstip', 'counter'])
        for k in flowmap.keys():
            val = flowmap[k].value
            # Add your code here (small suggestion for L4 protocol)
            # proto = (k.proto == 17 and "udp" or k.proto == 6 and "tcp" or "unk")
            srcip = str(int2ip(k.src_ip))
            dstip = str(int2ip(k.dst_ip))
            counter = val
            df.loc[len(df)] = [srcip, dstip, counter]

        print(df.sort_values(['counter', 'srcip', 'dstip']))
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break

b.remove_xdp(device, flags)
