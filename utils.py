import frida, os, json, sys
import re
import codecs
import re
from jinja2 import Environment, FileSystemLoader

file_loader = FileSystemLoader('templates')
env = Environment(loader=file_loader)

init_method_names = ['<clinit>', '<init>']
soot_method_signature_regex = "^<[a-zA-Z0-9$\.]+: [a-zA-Z0-9\[\]$\.]+ [a-zA-Z0-9$\.]+\([a-zA-Z0-9$,\s\.\[\]]*\)>$"


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
    if not re.match(r"^<[a-zA-Z0-9$\.]+: [a-zA-Z0-9\[\]$\.]+ [a-zA-Z0-9$\.]+\([a-zA-Z0-9$,\s\.\[\]]*\)>$",
                    method_signature):
        print('invalid soot signature : {}'.format(method_signature))
        return None
    method_data = dict()
    method_data['class_name'] = method_signature[method_signature.find('<') + 1:method_signature.find(":")]
    method_data['return_type'] = method_signature.split(" ")[1]
    method_data['method_name'] = method_signature.split(" ")[2][:method_signature.split(" ")[2].find("(")]
    method_data['parameters'] = method_signature[method_signature.find("(") + 1:method_signature.find(")")].split(",")
    if not method_data['parameters'][0]:
        method_data['parameters'] = list()

    if method_data['method_name'] in init_method_names:
        method_data['method_name'] = '$init'

    if not re.match(r'\A[\w-]+\Z', method_data['method_name']):
        return None
    return method_data


def generate_method_hook(method_data):
    template = env.get_template('java_method_hook.js')
    arguments = list()
    string_parameters = list()
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
    template = env.get_template('finder.js')
    return template.render(
        patterns=patterns,
    )


def generate_trace_script(method_hooks_list):
    template = env.get_template('trace_template.js')
    return template.render(method_hooks=method_hooks_list)


def generate_trace_script_from_method_sig(method_signature):
    method_data = get_method_data(method_signature)
    method_hooks = list()
    if method_data:
        method_hooks.append(generate_method_hook(method_data))
    return generate_trace_script(method_hooks)


def generate_tracer_js(scriptName, txtScript):
    script_dir = "__handlers__"
    if not os.path.exists(script_dir):
        os.makedirs(script_dir)
    tracer_file_path = os.path.join(script_dir, scriptName + ".js")
    with codecs.open(tracer_file_path, 'w', 'utf-8') as f:
        f.write(txtScript)
    return tracer_file_path


def get_method_hooks(method_signatures, class_filter, method_filter):
    generated_method_hooks = list()
    method_sigs = list()
    count = 0
    for method in method_signatures:
        if not method in method_sigs:
            method_sigs.append(method)
    for method_sig in method_sigs:
        method_data = get_method_data(method_sig)
        # if method_data and 'Location' in method_data['method_name']:
        generated_method_hook = generate_method_hook(method_data)
        generated_method_hooks.append(generated_method_hook)
        count += 1
    print(count)
    return generated_method_hooks


def connect(script, message_callback_function, app_name="Gadget"):
    device = frida.get_usb_device()
    try:
        session = device.attach(app_name)
    except Exception as e:
        print('[ERROR]: ' + str(e))
        sys.exit()
    try:
        # print(script)
        generate_tracer_js('test', script)
        loaded_script = session.create_script(script)
        loaded_script.on('message', message_callback_function)
        loaded_script.load()
    except Exception as e:
        print('[ERROR]: ' + str(e))
        sys.exit()
    return session
