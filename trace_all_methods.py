import frida, os, json, sys
from jinja2 import Environment, FileSystemLoader

import utils

def on_message(message, data):
    print(message)

template = utils.env.get_template('get_all_methods.js')

script = template.render()

utils.connect(script, on_message)
