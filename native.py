"""
This script uses Frida Gadget to connect to a running process on Android and hook all libc-syscall wrappers
"""

import subprocess
import json

# get syscall wrappers list
syscalls = json.load(open("libc_syscall_wrappers_list.json"))

# Build the process command
command = list()
command.append("frida-trace")
command.append("-U")
command.append("Gadget")

# Append each syscall wrapper to the frida-trace command line
for syscall in syscalls:
    command.append("-i")
    command.append(syscall)

# Launch the process
p = subprocess.Popen(command,
                     stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT)

# Print stdout
for line in iter(p.stdout.readline, b''):
    print(">>> " + line.rstrip().decode("utf-8"))
