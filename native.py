import subprocess
import json


syscalls = json.load(open("result.json"))
syscalls.remove('clock_gettime')
command = list()
command.append("frida-trace")
command.append("-U")
command.append("Gadget")
# command.append("-i")
# command.append("ipc")
for syscall in syscalls:
    command.append("-i")
    command.append(syscall)


p = subprocess.Popen(command,
                     stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT)

for line in iter(p.stdout.readline, b''):
    print(">>> " + line.rstrip().decode("utf-8"))
