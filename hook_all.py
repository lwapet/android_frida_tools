from __future__ import print_function
import frida
import sys
import utils


device = frida.get_usb_device()
session = device.attach("Gadget")
script_str = """
Interceptor.attach(Module.findExportByName('libc.so', "connect"), {
    onEnter: function(args) {
        send("libc.so connect method called");
    }
    //, onLeave: function(retval) {
    //   retval.replace(0); // Use this to manipulate the return value
    //}
});
"""
def on_message(message, data):
    if message['type'] == 'error':
        print("[!] " + message['stack'])
    elif message['type'] == 'send':
        print("[i] " + str(message['payload']))
    else:
        print(message)

session = utils.connect(script_str, on_message)
sys.stdin.read()
