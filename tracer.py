#!/usr/bin/env python3
import frida, os, json, sys
import pprint
import subprocess
import time
import mongo_utils
from termcolor import colored
import codecs
import re
from jinja2 import Environment, FileSystemLoader

# _APP_DATA = mongo_utils.get_app_data("FE666E209E094968D3178ECF0CF817164C26D5501ED3CD9A80DA786A4A3F3DC4")
# intent_setFlags = "<android.content.Intent: void addFlags(int)>"


file_loader = FileSystemLoader('templates')
env = Environment(loader=file_loader)

init_method_names = ['<clinit>', '<init>']
method_hooks = list()

def get_method_data(method_signature):
    """
    Generate convenient dictionary containing method data
    :param method_signature: model : <class_name: return_type method_name(arg1,arg2)> (Soot model)
    example : <java.net.URL: java.net.URLConnection openConnection()>
    :return: a dict in the form :
    method_data = {
    "class_name",
    "return_type,
    "method_name,
    "parameters",
    }
    """
    soot_method_signature_regex = "^<[a-zA-Z0-9$\.]+: [a-zA-Z0-9\[\]$\.]+ [a-zA-Z0-9$\.]+\([a-zA-Z0-9$,\s\.\[\]]*\)>$"
    # check if argument signature match Soot syntax
    if not re.match(r"^<[a-zA-Z0-9$\.]+: [a-zA-Z0-9\[\]$\.]+ [a-zA-Z0-9$\.]+\([a-zA-Z0-9$,\s\.\[\]]*\)>$",
                    method_signature):
        print('invalid soot signature : {}'.format(method_signature))
        return None
    # Parse method signature string
    method_data = dict()
    method_data['class_name'] = method_signature[method_signature.find('<') + 1:method_signature.find(":")]
    method_data['return_type'] = method_signature.split(" ")[1]
    method_data['method_name'] = method_signature.split(" ")[2][:method_signature.split(" ")[2].find("(")]
    method_data['parameters'] = method_signature[method_signature.find("(") + 1:method_signature.find(")")].split(",")

    # Format parameters so they are script ready
    if not method_data['parameters'][0]:
        method_data['parameters'] = list()

    # Format method name to be script ready (in case of constructor)
    if method_data['method_name'] in init_method_names:
        method_data['method_name'] = '$init'

    if not re.match(r'\A[\w-]+\Z', method_data['method_name']):
        return None

    return method_data


def generate_method_hook(method_data):
    """
    Generates a frida script that will hook the method when loaded in frida
    :param method_data: a dict containing method data (class_name, method_name, return_type, params)
    :return: (str) A piece of script, ready to use in a frida script, be careful, this piece of script can't be
    loaded directly as it is in Frida. It has to be wrapped in an other script, see (generate_trace_script_method)
    """
    # load template
    template = env.get_template('java_method_hook.js')
    arguments = list()
    string_parameters = list()

    # avoid empty string in parameters and arguments when building the script
    for i in range(0, len(method_data['parameters'])):
        arguments.append("var_{}".format(i))
        string_parameters.append('"' + method_data['parameters'][i] + '"')

    if len(string_parameters) == 1 and string_parameters[0] == '\"\"':
        arguments = list()
        string_parameters = list()

    return template.render(
        class_name=method_data['class_name'],
        method_name=method_data['method_name'],
        return_type=method_data['return_type'],
        parameters=string_parameters,
        arguments=arguments
    )


def generate_finder_script(patterns):
    """
    From a javascript template, generates a script that find methods in apk from the given patterns
    :param patterns:  a dict in the form :
    patterns = {
    "class_name", # e.g (com.my.great.class, note that wild cards are accepted : *my.className*)
    "method_name, (wild cards accepted too)
    }
    :return: a string representing a frida script, ready to load in Frida
    """
    template = env.get_template('finder.js')
    return template.render(
        patterns=patterns,
    )


def generate_trace_script(method_hooks_scripts):
    """
    Given a list of method_hooks_scripts (see generate_method_hook function), this function generates a trace script
    that will hook given method scripts.
    :param method_hooks_list: a list of method hook scripts previously generated
    :return:  a frida script (as string), ready to load in Frida
    """
    template = env.get_template('trace_template.js')
    return template.render(method_hooks=method_hooks_scripts)


def generate_trace_script_from_method_sig(method_signature):
    """
    This function generates a single, ready to use frida script form a given method signature.
    This is useful when you want to do some testing on a apk about a single method
    :param method_signature:  model : <class_name: return_type method_name(arg1,arg2)> (Soot model)
    :return: a frida script (as string), ready to load in Frida
    """
    method_data = get_method_data(method_signature)
    method_hooks = list()
    if method_data:
        method_hooks.append(generate_method_hook(method_data))
    return generate_trace_script(method_hooks)


def generate_tracer_js(scriptName, txtScript):
    """
    This function output a given script in a js file. Use it to debug your script
    :param scriptName: name of the script to be outputed
    :param txtScript: a string containing the actual script
    :return: the path of the created file
    """
    script_dir = "__handlers__"
    if not os.path.exists(script_dir):
        os.makedirs(script_dir)
    tracer_file_path = os.path.join(script_dir, scriptName + ".js")
    with codecs.open(tracer_file_path, 'w', 'utf-8') as f:
        f.write(txtScript)
    return tracer_file_path


def get_method_hooks(method_signatures):
    """
    This function return a list of method hook scripts from a list of method signatures
    :param method_signature: model : <class_name: return_type method_name(arg1,arg2)> (Soot model)
    :return: a list of method hooks scripts
    """
    generated_method_hooks = list()
    method_sigs = list()
    for method in method_signatures:
        if not method in method_sigs:
            method_sigs.append(method)
    for method_sig in method_sigs:
        method_data = get_method_data(method_sig)
        generated_method_hook = generate_method_hook(method_data)
        generated_method_hooks.append(generated_method_hook)
    return generated_method_hooks


def connect(script, message_callback_function, app_name="Gadget"):
    """
    This function connects a frida client to a running frida server on a device.
    It also loads the given script and register a message callback function to receive messages from frida server
    when the script is running
    :param script: the script to be loaded by frida when connected
    :param message_callback_function: a callback function that will process incoming messages from frida server
    :param app_name: the name of the process to instrument with frida. By default it is always Gadget when using
    Frida Gadget with an apk on an Android device.
    :return: the current Frida session
    """
    # Get running devices (can be an avd) try to attach our client to it.
    device = frida.get_usb_device()
    try:
        session = device.attach(app_name)
    except Exception as e:
        print('[ERROR]: ' + str(e))
        sys.exit()
    try:
        generate_tracer_js('test', script)  # generate the script in a file for debug
        loaded_script = session.create_script(script)  # create the frida script
        loaded_script.on('message', message_callback_function)  # register the callback function
        loaded_script.load()  # load the script in frida server
    except Exception as e:
        print('[ERROR]: ' + str(e))
        sys.exit()
    return session


def launch_app_on_adb(package_name, activity_name=None):
    """
    Helper function that start a given apk on a running avd
    :param package_name: the full package name of the apk
    :param activity_name: (optional), the apk start activity
    """
    if activity_name:
        launch_command = ["adb", "shell", "am", "start", "-n", package_name + "/" + activity_name]
    else:
        launch_command = ["adb", "shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"]
    # Launch app
    p = subprocess.Popen(launch_command,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    # read stdout
    for line in iter(p.stdout.readline, b''):
        print(">>> " + line.rstrip().decode("utf-8"))


def method_filter(class_name, method_name, method_list):
    """
    This function returns the first method in the method list that match the given class_name and method_name
    :param class_name: class name to match in the list
    :param method_name: method name to match in the list
    :param protected_method_list: method list to apply the filter
    :return: a method
    """
    for method in method_list:
        method_data = get_method_data(method['method_signature'])
        if method_data['class_name'] == class_name and method_data['method_name'] == method_name:
            return method
    return None


def collect_finder_methods(message, data):
    if ('system_message' in message['payload']):
        message = json.loads(message['payload'])
    else:
        global method_hooks
        method_data = json.loads(message['payload'])
        method_hook = generate_method_hook(method_data)
        print(colored('[FINDER] - New method found : {} {}.{}({})'.format(method_data['return_type'],
                                                                          method_data['class_name'],
                                                                          method_data['method_name'],
                                                                          method_data['parameters']), "blue"))
        method_hooks.append(method_hook)


def message_function(message, data):
    pprint.pprint(message)
    print('\n\n')


def run():
    global methods_hooks
    patterns = [
    {
        "class_name": "*",
        "method_names": ['*']
    },
    # {
    #     "class_name": "android.app.JobSchedulerImpl",
    #     "method_names": ["schedule"]
    # },
    # {
    #
    #     "class_name": "java.net.URL",
    #     "method_names": ["openConnection"]
    # }
]

    # Launch app
    # package_name = 'super'
    # activity_name = 'super.superActivity'
    # launch_app_on_adb(package_name, activity_name)

    # Wait before starting script injection. App will wait for script injection see https://www.frida.re/docs/gadget/
    # time.sleep(2)

    # method_list = list()
    # open_conn_sig = "<java.net.URL: java.net.URLConnection openConnection()>"
    # sig = "<android.view.ViewManager: void addView(android.view.View,android.view.ViewGroup$LayoutParams)>"
    # sig2 = "<android.app.Activity: void onCreate(android.os.Bundle)>"

    # data = get_method_data(sig)
    # data2 = get_method_data(sig2)
    # hook = generate_method_hook(data)
    # hook2 = generate_method_hook(data2)
    # method_hooks.append(hook)
    # method_hooks.append(hook2)
    # method_list.append(open_conn_sig)

    # method_hooks = get_method_hooks(method_list, None, None)
    # trace_script = generate_trace_script(method_hooks)
    # Generate trace script from method hooks
    app_methods = json.load(open('apks/locker-fe666e209e094968d3178ecf0cf817164c26d5501ed3cd9a80da786a4a3f3dc4_app_methods.json'))
    method_hooks = list()
    app_library_methods = json.load(open('apks/locker-fe666e209e094968d3178ecf0cf817164c26d5501ed3cd9a80da786a4a3f3dc4_library_methods.json'))
    all_methods = app_methods + app_library_methods
    for app_method in all_methods:
        method_data = get_method_data(app_method)
        if method_data:
            hook = generate_method_hook(method_data)
            method_hooks.append(hook)
    # finder_script = generate_finder_script(patterns)
    # finder_session = connect(finder_script, collect_finder_methods)
    trace_script = generate_trace_script(method_hooks)
    trace_session = connect(trace_script, message_function) # connect to frida server on avd and inject script

    # Read stdin
    sys.stdin.read()



if __name__ == "__main__":
    run()
