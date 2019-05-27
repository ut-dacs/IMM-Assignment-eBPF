#!/usr/bin/python
from bcc import BPF
from subprocess import call

prog = """
#include <uapi/linux/bpf.h> //standard bpf header
int hello(void *ctx) {
  bpf_trace_printk("Hello, World!\\n"); //print on trace buffer
  return 0;
};
"""
b = BPF(text=prog) #declare program object
fn = b.load_func("hello", BPF.KPROBE) #take a pointer to the function in the code
b.attach_kprobe(event="sys_clone", fn_name="hello") #attach the function to sys_clone system call
call(["cat", "/sys/kernel/debug/tracing/trace_pipe"]) #read  from trace buffer
