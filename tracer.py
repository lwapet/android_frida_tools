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
import getopt

# _APP_DATA = mongo_utils.get_app_data("FE666E209E094968D3178ECF0CF817164C26D5501ED3CD9A80DA786A4A3F3DC4")
# intent_setFlags = "<android.content.Intent: void addFlags(int)>"


file_loader = FileSystemLoader('templates')
env = Environment(loader=file_loader)

init_method_names = ['<clinit>', '<init>']
method_hooks = list()
added_lines_in_new_block = 0

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
        #print('invalid soot signature : {}'.format(method_signature))
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


def connect(script, message_callback_function,  app_name="Gadget"):
#def connect(script, message_callback_function,  app_name="com.android.chrome"):

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
        # added by Lavoisier
        print("Calling the rpc callback")
        loaded_script.exports.callhooksfunction();
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
    print("\n message received:" +  json.dumps(message))
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
    

def collect_finder_methods_and_write_in_json_file(message, data):   
    
    if ('system_message' in message['payload']):
        message = json.loads(message['payload'])
    else:
        method_data = json.loads(message['payload'])
        print(colored('[FINDER] - New method found : {} {}.{}({})'.format(method_data['return_type'],
                                                                          method_data['class_name'],
                                                                          method_data['method_name'],
                                                                          method_data['parameters']), "blue"))
        
        global output_json_file
        global file_methods
        global added_lines_in_new_block  
        

        added_lines_in_new_block =  added_lines_in_new_block + 1
        file_methods.append(get_method_signature_from_data(method_data))

        if( added_lines_in_new_block > 100):
            added_lines_in_new_block = 0
            print("***** writing in output file")
            with open(output_json_file, 'w') as outfile:
                json.dump(file_methods, outfile, indent=2)

     

       
       

       


def message_function(message, data):
    pprint.pprint(message)
    print('\n\n')

def get_method_signature_from_data(method_data):
    parameters = ",".join(method_data['parameters'])
    method_name = method_data['method_name']
    if method_name == "$init":
        method_name = '<init>' #every method will be init, even clinit
    return "<" + method_data['class_name'] + ": " + method_data['return_type'] +  " " + method_name + "(" + parameters + ")>" 






    
   


def trace_only_the_same_app(argv):
    ##### ##### ##### Usage 1: Testing the same application with a certain number of "tested" methods
    ##### Options : -n the number of methods (named in this script n_method)
    ##### Notes: I traced the same application  (locker-fe666e209e094968d3178ecf0cf817164c26d5501ed3cd9a80da786a4a3f3dc4)
    #####           using the json file as input 
    #####      apks/json_inputs/locker-fe666e209e094968d3178ecf0cf817164c26d5501ed3cd9a80da786a4a3f3dc4_app_methods_without_class_not_found_error_'+str(n_methods)+'_entries.json'))
    #####       which depends on the number of methods I whant to trace
    #####     Notes that json input files have been generated by another script before, using this script.  
    ##### Managing options

    try:
        opts, args = getopt.getopt(argv,"hn:",["n_methods="])
    except getopt.GetoptError:
        print('tracer.py -n <n_methods>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('tracer.py -n <n_methods> ')
            sys.exit()
        elif opt in ("-n", "--n_methods"):
            n_methods = arg

    ##### Generating method hooks
    app_methods = json.load(open('apks/json_inputs/locker-fe666e209e094968d3178ecf0cf817164c26d5501ed3cd9a80da786a4a3f3dc4_app_methods_without_class_not_found_error_'+str(n_methods)+'_entries.json'))
    method_hooks = list()
    all_methods = app_methods
    methods_traced = 0
    methods_candidates = 0
    for app_method in all_methods:
        methods_candidates = methods_candidates + 1
        method_data = get_method_data(app_method)
        if method_data:
            hook = generate_method_hook(method_data)
            method_hooks.append(hook)
            methods_traced = methods_traced + 1
    print('method_traced = ', methods_traced, ', method_candidates = ', methods_candidates)

    ##### Tracing the app
    trace_script = generate_trace_script(method_hooks)
    trace_session = connect(trace_script, message_function) # connect to frida server on avd and inject script
    
    # Read stdin
    sys.stdin.read()

def replaceCharInWord(word,char_to_change,replacement_char):
    list_ = word.split(char_to_change)
    list_= replacement_char.join(list_)
    return list_


def generate_odile_script(method_regex_, class_regex_, script_template_folder, script_template_file_name):
    """
    Generates the index.ts script in the script_template_folder, 
    using script_template_file_name located in the same folder
    The simple rendering operation will replace method_regex  and class_regex with the corresponding values 
    passed as parameters in this folder.
    """
    # load template
    env1 = Environment(loader=FileSystemLoader(script_template_folder))
    template = env1.get_template(script_template_file_name)
    return template.render( 
        method_name_regex=method_regex_,
        class_name_regex=class_regex_ 
        )




def generate_odile_method_regex(method_datas):
    """
    Generates the final method regex that will be used as input of Odile
    :param method_datas: a dict containing methods datas (class_name, method_name, return_type, params)*
    :return: (str) A piece of script, ready to use in odile script, be careful, this piece of script can't be
    loaded directly as it is in Odile. It has to be wrapped in an other script, see (generate_odile_script_method)
        Example :   new RegExp (['checkWifiSecurity',
                        '|onServiceConnected',
                        '|onBound',
                             ...
                        '|resumeScan'
                    ].join(''))
    """
    final_method_regex = "new RegExp (['"
    methods_added = list()
    if len(method_datas) == 0:
        final_method_regex = final_method_regex + "'].join(''))"
    elif len(method_datas) == 1:
        final_method_regex = final_method_regex + method_datas[0]["method_name"]  + "'].join(''))"
    else: 

       
        final_method_regex = final_method_regex + method_datas[0]["method_name"] + "',"
        for i in range(1, len(method_datas) - 1):
            if method_datas[i]["method_name"] not in methods_added:
                methods_added.append(method_datas[i]["method_name"])
                final_method_regex = final_method_regex + "\n\t\t\t '|" + method_datas[i]["method_name"] + "',"    
        final_method_regex = final_method_regex + "\n\t\t\t '|" + method_datas[len(method_datas) - 1]["method_name"] + "' \n ].join(''))"
    print(" ***** ***** *****  final method regex for the current group of methods : " + final_method_regex)
    return final_method_regex

def generate_odile_class_regex(method_datas):
    """
    Generates the final method regex that will be used as input of Odile
    :param method_datas: a dict containing methods datas (class_name, method_name, return_type, params)*
    :return: (str) A piece of script, ready to use in odile script, be careful, this piece of script can't be
    loaded directly as it is in Odile. It has to be wrapped in an other script, see (generate_odile_script_method)
        Example :   new RegExp (['com\.zoner\.android\.antivirus\.svc\.NetMonitor',
                        '|com\.zoner\.android\.antivirus\.svc\.ServiceBinder',
                        '|com\.zoner\.android\.antivirus\.ui\.ActScanResults',
                                ...
                        '|com\.zoner\.android\.antivirus\.ui\.ActScanResults'
                    ].join(''))
    """
    final_class_regex = "new RegExp (['"
    classes_added = list()
    if len(method_datas) == 0:
        final_class_regex = final_class_regex + "'].join(''))"
    elif len(method_datas) == 1:
        final_class_regex = final_class_regex + replaceCharInWord(method_datas[0]["class_name"],".", "\\.")  + "'].join(''))"
    else: 
        final_class_regex = final_class_regex + replaceCharInWord(method_datas[0]["class_name"],".", "\\.") + "',"
        for i in range(1, len(method_datas) - 1):
            if method_datas[i]["class_name"] not in classes_added:
                classes_added.append(method_datas[i]["class_name"])
                final_class_regex = final_class_regex + "\n\t\t\t '|" + replaceCharInWord(method_datas[i]["class_name"],".", "\\.") + "',"

        final_class_regex = final_class_regex + "\n\t\t\t '|" + replaceCharInWord(method_datas[i]["class_name"],".", "\\.") + "' \n ].join(''))"
    print(" ***** ***** *****  final method regex for the current group of methods : " + final_class_regex)
    return final_class_regex









def run(argv):
    ##### ##### ##### Tracer script 
    ##### options depends on usage of this scritp  (the uncommented part)
    
    # trace_only_the_same_app(argv)
    
    ##### ##### ##### Usage 2: Retriving all methods of an arbitrary app 
    ##### Options : -a  the apk path  (should finish with '.apk')
    ##### Note : The app should be already instrumented and started in an emulator, 
     
    ##### ##### ##### Usage 1: Testing the same application with an input json file containing methods
    ##### Options : -n the number of methods (named in this script n_method)
    ##### Notes: I traced the same application  (locker-fe666e209e094968d3178ecf0cf817164c26d5501ed3cd9a80da786a4a3f3dc4)
    #####           using the json file as input 
    #####      apks/json_inputs/locker-fe666e209e094968d3178ecf0cf817164c26d5501ed3cd9a80da786a4a3f3dc4_app_methods_without_class_not_found_error_'+str(n_methods)+'_entries.json'))
    #####       which depends on the number of methods I whant to trace
    #####     Notes that json input files have been generated by another script before, using this script.  
    ##### ##### ##### Usage 3: Generating the Odile tracer script for an arbitrary app knowing only the method json file list
    #####-O for Odile usage, the tracer.py will just generate the tracing script 
	#####-p the tracer template (p for patron) file to modify
	#####-f the method json file 
	#####-r the folder where to put the result file
    ##### Managing options


    global output_json_file
    global file_methods
    global added_lines_in_new_block
    file_methods = list()
    added_lines_in_new_block = 0
    trace_app = False
    global json_methods_files
    collect_methods = False
    generate_Odile_tracer_script = False
    Odile_tracer_script_template = ''
    output_result_folder = ""
    print ("argv = " + str(sys.argv[1:]))


    try:
        opts, args = getopt.getopt(sys.argv[1:],"ho:tf:Op:r:",["output_json_file=","trace_app","json_methods_file=",
        "generate_Odile_tracer_script","Odile_tracer_script_template=","output_result_folder="])
    except getopt.GetoptError:
        print('error : tracer.py -o <output_json_file> -t -f <json_methods_file> -O <generate Odile tracer script>' +  
                ' -p < Odile tracer template file> -r <Folder where the index.ts file will be generated if -O is activated>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('tracer.py -o <output_json_file> -t (if you want to trace apk) -f <json_methods_file>')
            sys.exit()
        elif opt in ("-o", "--output_json_file"):
            print('processing o')
            output_json_file = arg
            collect_methods = True
        elif opt in ("-t", "--trace_app"):
            print('processing t')
            trace_app = True
        elif opt in ("-f", "--json_methods_file"):
            print('processing f')
            json_methods_files = arg
        elif opt in ("-O", "--generate_Odile_tracer_script"):
            print('processing O')
            generate_Odile_tracer_script = True
        elif opt in ("-p", "--Odile_tracer_script_template"):
            print('processing p')
            Odile_tracer_script_template = arg 
        elif opt in ("-r", "--output_result_folder"):
            print('processing r ' + arg)
            output_result_folder = arg 
    


    if(generate_Odile_tracer_script):
        print("***** ***** ***** Generating Odile scripts")
        app_methods = json.load(open(json_methods_files))
        method_datas = list()
        for app_method in app_methods:
            method_data = get_method_data(app_method)
            if method_data: 
                method_datas.append(method_data)

        method_regex_ = generate_odile_method_regex(method_datas)
        class_regex_ = generate_odile_class_regex(method_datas)

        print (" ***** ***** ***** Odile_tracer_script_template : " + Odile_tracer_script_template)  
        script_template_folder = os.path.dirname(Odile_tracer_script_template)
        script_template_file_name = os.path.basename(Odile_tracer_script_template)
        print(" ***** ***** ***** script_template_folder =  " + script_template_folder)
        print(" ***** ***** ***** script_template_file = " + script_template_file_name)
        odile_tracer_scprit = generate_odile_script(method_regex_, class_regex_, script_template_folder, script_template_file_name)
       
        index_file = output_result_folder + "/index.ts"
        print(" ***** ***** ***** index_file = " + index_file)
        f = open(index_file, "w")
        f.write(odile_tracer_scprit)
        f.close()

        return None

    
    if(trace_app):
        print(" ***** ***** ***** Tracing app ")
        ##### Generating method hooks
        app_methods = json.load(open(json_methods_files))
        method_hooks = list()
        all_methods = app_methods
        methods_tested = 0
        methods_candidates = 0
        for app_method in all_methods:
            methods_candidates = methods_candidates + 1
            method_data = get_method_data(app_method)
            if method_data:
                hook = generate_method_hook(method_data)
                method_hooks.append(hook)
                methods_tested = methods_tested + 1
        print(' ***** ***** ***** Method_tested = ', methods_tested, ', method_candidates = ', methods_candidates)

        ##### Tracing the app
        trace_script = generate_trace_script(method_hooks)
        trace_session = connect(trace_script, message_function) # connect to frida server on avd and inject script
        
        # Read stdin
        sys.stdin.read()
        return None

    if(collect_methods):
        patterns = [
        {
            "class_name": "*",
            "method_names": ['*']
        }]
        if(os.path.exists(output_json_file)):
            os.remove(output_json_file)
            out_file = open(output_json_file, 'w+') 
            json.dump(list(), out_file, indent=2)

        finder_script = generate_finder_script(patterns)
        finder_session = connect(finder_script, collect_finder_methods_and_write_in_json_file)
        #generating the json file 
    
        # Read stdin
        sys.stdin.read()
        return None

if __name__ == "__main__":
    run(sys.argv[1:])
