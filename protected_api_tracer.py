import frida, os, json, sys
import utils
import pprint
import subprocess
import time
import mongo_utils
from termcolor import colored

_APP_DATA = mongo_utils.get_app_data("FE666E209E094968D3178ECF0CF817164C26D5501ED3CD9A80DA786A4A3F3DC4")
open_conn_sig = "<java.net.URL: java.net.URLConnection openConnection()>"
intent_setFlags = "<android.content.Intent: void addFlags(int)>"
launch_command = ["adb", "shell", "monkey", "-p", _APP_DATA['package_name'], "-c", "android.intent.category.LAUNCHER",
                  "1"]
start_activity = _APP_DATA['pkg_name'] + '.StartShowActivity'
launch_command_bis = ["adb", "shell", "am", "start", "-n", _APP_DATA['pkg_name'] + "/" + start_activity]


def get_protected_method_permissions(class_name, method_name, protected_method_list):
    for method in protected_method_list:
        method_data = utils.get_method_data(method['method_signature'])
        if method_data['class_name'] == class_name and method_data['method_name'] == method_name:
            return method['permissions']
    return None


def message_function(message, data):
    pprint.pprint(message)
    # payload = json.loads(message['payload'])
    # method_permissions = get_protected_method_permissions(payload['class_name'], payload['method_name'], _APP_DATA)
    # if method_permissions:
    #     print(method_permissions)
    print('\n\n')


## Launch app
# p = subprocess.Popen(launch_command_bis,
#                      stdout=subprocess.PIPE,
#                      stderr=subprocess.STDOUT)

## read stdout
# for line in iter(p.stdout.readline, b''):
#     print(">>> " + line.rstrip().decode("utf-8"))


# Wait before starting script injection
# time.sleep(2)

# Generate method hooks

# for method in _APP_DATA['protected_methods']:
#     if method['api_level'] <= 19:
#         method_list.append(method['method_signature'])


# method_list.append(open_conn_sig)
# method_list.append(intent_setFlags)


# method_hooks = utils.get_method_hooks(method_list, None, None)
# Generate trace script from method hooks
# trace_script = utils.generate_trace_script(method_hooks)

# Connect to frida server and start hooking
method_hooks = list()
is_script_finished = False


def collect_finder_methods(message, data):
    if ('system_message' in message['payload']):
        message = json.loads(message['payload'])
        if (message['system_message'] == 'script_finished'):
            global is_script_finished
            is_script_finished = True
    else:
        global method_hooks
        method_data = json.loads(message['payload'])
        method_hook = utils.generate_method_hook(method_data)
        print(colored('[FINDER] - New method found : {} {}.{}({})'.format(method_data['return_type'],
                                                                          method_data['class_name'],
                                                                          method_data['method_name'],
                                                                          method_data['parameters']), "blue"))
        method_hooks.append(method_hook)


patterns = [
    {
        "class_name": "com.android.server.job*",
        "method_names": ["schedule"]
    },
    {
        "class_name": "android.app.JobSchedulerImpl",
        "method_names": ["schedule"]
    },
    # {
    #
    #     "class_name": "java.net.URL",
    #     "method_names": ["openConnection"]
    # }
]

trace_script = utils.generate_finder_script(patterns)
current_session = utils.connect(trace_script, collect_finder_methods)
if is_script_finished:
    if len(method_hooks) == 0:
        print(colored('No methods found', "red"))
    new_trace_script = utils.generate_trace_script(method_hooks)
    print(new_trace_script)
    utils.connect(new_trace_script, message_function)

# Read stdin
sys.stdin.read()
