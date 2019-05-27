#!/usr/bin/python
from bcc import BPF
import time

# load BPF program
b = BPF(text="""
#include <uapi/linux/bpf.h> //BPF Header
#include <linux/in.h> //Inet Header (for nthos etc..)
#include <linux/if_ether.h> //Ethernet Header
BPF_HASH(simplemap, u64, u64); //Define a simple hashmap with a u64 as key and u64 as value
int xdp_prog1(struct CTXTYPE *ctx) {  //xdp function (the parameter contains the ethernet frame and the size)
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data; //convert data to ethhdr structure
    u64 zero = 0, *val;
    val = simplemap.lookup_or_init(&zero,&zero); //get value at index 0 of the hashmap (or init index 0 with 0). Return a POINTER!
    if (val){ //if the pointer is valid =>> pointer !=0
       *val += 1; // dereference the pointer and increment the value
    }
    return XDP_PASS; //let the packet flow
}
""", cflags=["-w", "-DCTXTYPE=xdp_md"])

fn = b.load_func("xdp_prog1", BPF.XDP) #get function from the code
b.attach_xdp("eno1", fn, 0) #attach function to interface

simplemap = b.get_table("simplemap") #get table from the code
print("Starting")
while 1:
    try:
	for k in simplemap.keys(): #for each key (we have just one) print the value
        	print(simplemap[k].value)
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break
b.remove_xdp(device, 0) #remove program from the interface
