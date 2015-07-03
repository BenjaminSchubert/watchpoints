# watchpoints
A Linux kernel module for setting up watchpoints without going through ptrace

This module aims to be a lightweight replacement to the ptrace module for setting and reporting values.

## Usage

#### Compilation
To compile watchpoints, hit `make` in the top directory.

#### Loading
Watchpoints is loaded as a normal kernel module as `insmod ${path_to_watchpoints.ko}`.

#### Watching an address
An watchpoint can only be set by the process owning the address space. To watch an address, send an ioctl to `/dev/watchpoints`, with code `1` and a pointer to a struct of form :

    struct message {
      long data_ptr,
      long data_size
    };

with pid, the pid of the running process, data_ptr, the pointer to the data to be watched and data_size, the size of the data to watch.

Any modificiation to the data can then be read in `/dev/watchpoints`. Be careful though, once read, the data in `/dev/watchpoints` is deleted.
