import frida

import frida
import sys



def on_message(message, data):
    print(message)


device = frida.get_usb_device(3) # added timeout to wait for 3 seconds
session = device.attach("Gadget")
script = session.create_script(open("/Users/lgitzing/Development/work/FridaServer/open.js").read())
script.on('message', on_message)
script.load()
sys.stdin.read()
