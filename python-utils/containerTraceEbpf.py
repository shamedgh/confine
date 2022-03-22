#! /usr/bin/python3
#
# Adapted from: execsnoop
#
# Copyright 2021 PJR Corp.
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 07-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from bcc.utils import ArgString, printb
import bcc.utils as utils
import re
import time
from collections import defaultdict
from time import strftime
import subprocess
from sys import stderr
import signal
import sys

max_args = str(100)
container_processes = [ b"containerd-shim" ]
container_regex = b""
print("Watching for containers started with processes named:")
for name in container_processes:
    container_regex += b"%s | " % name
    printb(b"\t- %s" % name)
container_regex = container_regex[:-3]
process_re = re.compile(container_regex)

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>

// For file path:
#include <linux/fdtable.h>

#define ARGSIZE  128

enum event_type {
    EVENT_EXEC_ARG,
    EVENT_EXEC_RETURN,
    EVENT_OPEN,
};

// TODO use PATH_MAX
const static int STRSIZE = NAME_MAX > ARGSIZE ? NAME_MAX : ARGSIZE;

struct data_t {
    enum event_type type;
    // Possibly we will want to track cgroups, but right now we don't use it
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    char comm[TASK_COMM_LEN];
    
    // Overloaded to keep the size of this struct down:
    // for exec, this is the argv
    // for open, this is the filename
    char strdata[STRSIZE];
    int retval;
};
struct val_t {
    u64 id;
    char comm[TASK_COMM_LEN];
    const char *fname;
    int flags; //unused
};
BPF_HASH(infotmp, u64, struct val_t);
BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(ret_val_map, struct data_t, 1);


static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read(data->strdata, sizeof(data->strdata), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

// TODO we can (possibly) store data on the kernel side in a BPF_HASH
//      to reduce the amount of perf events
int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_EXEC_ARG;

    __submit_arg(ctx, (void *)filename, &data);

    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_EXEC_RETURN;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int trace_syscall__open(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t val = {};

    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.fname = filename;
        val.flags = flags; // unused, just to match other code
        infotmp.update(&id, &val);
    }
    return 0;
};

static int unwind_path(struct path* path_ptr, char* const path_string)
{
    struct path the_path = {};
    struct dentry *dir_de = NULL;
    struct dentry *parent = NULL;
    struct qstr dn = {};

    bpf_probe_read(&the_path, sizeof(the_path), path_ptr);
    bpf_probe_read(&dir_de, sizeof(dir_de), &the_path.dentry);

    int parent_count = 0;
    while (dir_de) {
        ++parent_count;
        bpf_probe_read(&parent, sizeof(parent), &dir_de->d_parent);
        dir_de = dir_de == parent ? NULL : parent;
        if (parent_count > 55) { // prevent eBPF VM from thinking we have an endless loop
            bpf_trace_printk("   IN TOO DEEP!  BAILING OUT***********************");    
            return -1;
        }
    }
    // Build up the string by iterating over the parent dentries until we get to the right one each time.
    // We do this to avoid blowing the stack, since we're limited on stack space.
    // Skip the first entry, it's always "/"
    char* path_insert = path_string;
    for (int i = parent_count-1; i >= 0; --i) {
        bpf_probe_read(&dir_de, sizeof(dir_de), &the_path.dentry);
        for (int j = 0; j < i; ++j) {
            bpf_probe_read(&parent, sizeof(parent), &dir_de->d_parent);
            dir_de = parent;
        }
        bpf_probe_read(&dn, sizeof(dn), &dir_de->d_name);
        if (path_insert) {
            int str_len = 0;
            unsigned char *name = NULL; 
            bpf_probe_read(&name, sizeof(name), &dn.name);
            //str_len = bpf_probe_read_str(path_insert, PATH_MAX, name);
            path_insert += str_len;
            bpf_trace_printk("   parent dir=%s, %d", name, str_len);
        }
        else {
            bpf_trace_printk("   parent dir=%s", dn.name);
        }
    }
    //*insertPos = 0; // null terminate

    bpf_trace_printk("   loop count: %d\\n", parent_count);
    return path_insert - path_string;
}

#if 0
/**
 * Populate path_string for the supplied file descriptor.
 * \return the size of the string
 */ 
int get_file_path(const int fd, char* const path_string) 
{
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    struct files_struct* files = NULL;
    struct fdtable* fdt = NULL;
    struct file** fdt_fd = NULL;
    struct file* my_file = NULL;
    
    bpf_probe_read(&files, sizeof(files), &curr->files);
    if (!files) {
        bpf_trace_printk("No Files.\\n");
        return -1;
    }
    bpf_probe_read(&fdt, sizeof(fdt), &files->fdt);
    bpf_probe_read(&fdt_fd, sizeof(fdt_fd), &fdt->fd);
    bpf_probe_read(&my_file, sizeof(my_file), &fdt_fd[fd]);
    return unwind_path(&my_file->f_path, NULL);
}
#endif

int do_ret_sys_open(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    u32 map_index = 0;
    struct data_t *data = ret_val_map.lookup(&map_index);
    struct fs_struct *fs = NULL;
    struct val_t *valp = infotmp.lookup(&id);
    
    if (valp == 0 || data == NULL) {  // missed entry
        return 0;
    }

    int fd = PT_REGS_RC(ctx); // This is the FD (when positive)
    // Ignore failed reads
    if (fd < 0)
        return 0;
    data->retval = fd;

    bpf_probe_read(&data->comm, sizeof(data->comm), valp->comm);
    bpf_probe_read(&data->strdata, sizeof(data->strdata), valp->fname);
    data->type = EVENT_OPEN;
    data->pid = id >> 32;

    bpf_probe_read(&fs, sizeof(fs), &curr->fs);
#define TRY_FDT_TABLE
#ifdef TRY_FDT_TABLE
    {
        struct files_struct* files = NULL;
        bpf_probe_read(&files, sizeof(files), &curr->files);
        if (!files)
            bpf_trace_printk("No Files.\\n");
        else 
        {
            struct fdtable* fdt = NULL;
            struct file** fdt_fd = NULL;
            struct file* my_file = NULL;
            bpf_probe_read(&fdt, sizeof(fdt), &files->fdt);
            bpf_probe_read(&fdt_fd, sizeof(fdt_fd), &fdt->fd);
            bpf_probe_read(&my_file, sizeof(my_file), &fdt_fd[fd]);
            unwind_path(&my_file->f_path, data->strdata);
            //bpf_probe_read_str(data->strdata, PATH_MAX, valp->fname);

        }
    }
#endif 
#if 0
    if (data->strdata[0] != '/') {
        bpf_trace_printk("open fd=%d, cpu#=%d, pid=%d", fd, curr->on_cpu, curr->pid);
        bpf_trace_printk("open fd=%d file=%s", fd, data->strdata);
        unwind_path(&fs->pwd, NULL);
        bpf_trace_printk("");
    }
#endif

    events.perf_submit(ctx, data, sizeof(*data));
    infotmp.delete(&id);

    return 0;
}

"""


#b.attach_kprobe(event="do_sys_open", fn_name="trace_syscall__open")
#b.attach_kprobe(event="do_sys_open", fn_name="trace_entry")
#b.attach_kretprobe(event="do_sys_open", fn_name="do_ret_sys_open")
# TODO openat? openat2?
# Check out https://www.kernel.org/doc/html/latest/filesystems/path-lookup.html
# When we do openat, we need to be careful about relative paths which may not start from pwd, but from a supplied FD!?!?

# header
# print("%-9s" % ("TIME"), end="")
# print("%-16s %-6s %-6s %3s %s" % ("PCOMM", "PID", "PPID", "RET", "ARGS"))

class EventType(object):
    EVENT_EXEC_ARG = 0
    EVENT_EXEC_RETURN = 1
    EVENT_OPEN = 2

class State(object):
    INACTIVE = 0
    STARTED = 1
    RUNNING = 2
    STOPPED = 3


# This is best-effort PPID matching. Short-lived processes may exit
# before we get a chance to read the PPID.
# This is a fallback for when fetching the PPID from task->real_parent->tgip
# returns 0, which happens in some kernel versions.
def get_ppid(pid):
    try:
        with open("/proc/%d/status" % pid) as status:
            for line in status:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except IOError:
        pass
    return 0

# process event

def printEvent(event):
    printb(b"%-9s" % strftime("%H:%M:%S").encode('ascii'), nl="")
    ppid = event.ppid if event.ppid > 0 else -1
    ppid = b"%d" % ppid if ppid > 0 else b"?"
    argv_text = b' '.join(argv[event.pid]).replace(b'\n', b'\\n')
    printb(b"%-16s %-6d %-6s %3d %s" % (event.comm, event.pid,
            ppid, event.retval, argv_text))

def getContainerId(args):
    for i, arg in enumerate(args):
        if arg == b'-id':
            return str(args[i+1])[2:-1]

def getState(args):
    #print ("Checking container state: " + str(args))
    if b'start' in args:
        return State.STARTED
    elif b'delete' in args:
        return State.STOPPED
    return State.RUNNING

def signal_term_handler(signal, frame):
    #print('got SIGTERM')
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_term_handler)

# loop with callback to process_event

class ContainerTraceEbpf():
    def __init__(self, filename):
        bpf_text_str = bpf_text.replace("MAXARG", max_args)

        # initialize BPF
        self.b = BPF(text=bpf_text_str)
        execve_fnname = self.b.get_syscall_fnname("execve")
        self.b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
        self.b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

        clone_fnname = self.b.get_syscall_fnname("clone")
        self.b.attach_kretprobe(event=clone_fnname, fn_name="do_ret_sys_execve")
        

        self.argv = defaultdict(list)
        self.state = { "1" : State.RUNNING }
        self.containerPids = []
        self.filename = filename
        #self.f = None
        

    def run(self, stop_run):

        self.f = open(self.filename, 'w')

        self.b["events"].open_perf_buffer(self.process_event)
        while 1:
            try:
                self.b.perf_buffer_poll()
                if stop_run():
                    self.b.cleanup()
                    print("stopping", file=self.f)
                    self.f.flush()
                    self.f.close()
                    break
            except KeyboardInterrupt:
                print("interrupt", self.f)
                self.f.flush()
                self.f.close()
                exit()

    def process_event(self, cpu, data, size):
        event = self.b["events"].event(data)

        # Add argument to argv array for use later
        if event.type == EventType.EVENT_EXEC_ARG:
            self.argv[event.pid].append(event.strdata)
       
        # This is the main event that reads the argv stored earlier
        elif event.type == EventType.EVENT_EXEC_RETURN:

        # Check if this is a container start up process
            if event.ppid in self.containerPids:
                argv_text = b' '.join(self.argv[event.pid]).replace(b'\n', b'\\n')
                print ("Container process: " + str(argv_text,'utf-8'), file=self.f)
                self.containerPids.append(event.pid)
            #print ("New PID list: " + str(containerPids))

            if process_re.match(event.comm):
            # printEvent(event)
                args = self.argv[event.pid]
            # Get the container ID
                id = str(getContainerId(args))
                new_state = getState(args)
                print("[%s] id=%s" % (new_state, id), file=self.f)
                if id not in list(self.state):
                    self.state[id] = new_state
                if self.state[id] == State.STARTED:
                    if new_state == State.RUNNING:
                        self.state[id] = new_state
                    # Start strace
                    #cmd = ['/usr/bin/strace', '-p', str(event.pid), '-f', '-o', "%s.log" % id, '--trace=open,openat']
                    #p = subprocess.Popen(cmd)
                    #print("Attached strace to Container %s (PID: %s)" % (id, event.pid))
                        self.containerPids.append(event.pid)
                elif self.state[id] == State.RUNNING:
                    if new_state == State.STOPPED:
                        self.state[id] = new_state
                        print("Container %s stopped" % id, file=self.f)

            try:
                del(self.argv[event.pid])
            except Exception:
                pass


        elif event.type == EventType.EVENT_OPEN:
            if (event.pid in self.containerPids):
                print ("Open, " + event.comm.decode("utf-8") + ", " + str(event.pid) + ", " + event.strdata.decode("utf-8") + ", " + str(event.retval), file=self.f)
            # TODO track the PID & filenames in a map

        else:
            print("Unknown event type: %d" % event.type, file=stderr)
        sys.stdout.flush()
        self.f.flush()


