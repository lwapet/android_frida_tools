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
import random
import os, fnmatch
import numpy as np
import matplotlib.pyplot as plt
import getopt
import matplotlib.cbook as cbook
# _APP_DATA = mongo_utils.get_app_data("FE666E209E094968D3178ECF0CF817164C26D5501ED3CD9A80DA786A4A3F3DC4")
# intent_setFlags = "<android.content.Intent: void addFlags(int)>"


file_loader = FileSystemLoader('templates')
env = Environment(loader=file_loader)

init_method_names = ['<clinit>', '<init>']
method_hooks = list()

def get_method_signature_from_data(method_data):
    parameters = ",".join(method_data['parameters'])
    method_name = method_data['method_name']
    if method_name == "$init":
        method_name = '<init>' #every method will be init, even clinit
    return "<" + method_data['class_name'] + ": " + method_data['return_type'] +  " " + method_name + "(" + parameters + ")>" 

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


def del_list_indexes(l, id_to_del):
    somelist = [i for j, i in enumerate(l) if j not in id_to_del]
    return somelist


def retain_list_indexes(l, id_to_retain):   #modif, pour avoir les méthodes distinctes
    somelist = [i for j, i in enumerate(l) if j in id_to_retain]
    return somelist

def generate_valid_methods():
    app_methods = json.load(open('apks/locker-fe666e209e094968d3178ecf0cf817164c26d5501ed3cd9a80da786a4a3f3dc4_app_methods.json'))
    app_library_methods = json.load(open('apks/locker-fe666e209e094968d3178ecf0cf817164c26d5501ed3cd9a80da786a4a3f3dc4_library_methods.json')) 
    all_methods = app_methods + app_library_methods
    indexes_to_remove = []
    final_methods_datas =  list()
    final_methods =  list()
    method_datas = list()

    methods_candidates = 0
    
    for app_method in all_methods:
        methods_candidates = methods_candidates + 1
        method_data = get_method_data(app_method)
        if(method_data):
            method_datas.append(method_data)
    
    FridaOutputFilepath = 'first_log'
    with open(FridaOutputFilepath) as fp:
        for cnt, line in enumerate(fp):
            print("Analysing Line {}: {}".format(cnt, line))
            if re.match(r"^(?:\b|(?<=_))Error: java.lang.ClassNotFoundException: Didn't find class(?=\b|_).*$",
                        line):
                print("Error line ", line, '\n split', line.split("\""))
                class_not_found = line.split("\"")[1]
                print(" \n class_not_found name = ", class_not_found)
                index_to_remove = 0
                for method_data in method_datas:
                    method_class_name = method_data['class_name']
                    if (method_class_name == class_not_found):
                        print("method to remove_ ", method_data['method_name'])
                        indexes_to_remove.append(index_to_remove)
                    index_to_remove = index_to_remove + 1 
            else:
                print('not an  ClassNotFoundException error: {} \n'.format(line))
                continue 
    final_methods_data = del_list_indexes(method_datas, indexes_to_remove)
    methods_retained = 0   
    for method_data in final_methods_data:
        methods_retained = methods_retained + 1
        final_methods.append(get_method_signature_from_data(method_data))
    print('method_candidates = ',methods_candidates)
    print('method_retained = ', methods_retained)
    with open('apks/json_inputs/locker-fe666e209e094968d3178ecf0cf817164c26d5501ed3cd9a80da786a4a3f3dc4_app_methods_without_class_not_found_error.json', 'w') as outfile:
        json.dump(final_methods, outfile, indent=2)


def intersect_methods_(json_input_file):
    groupA_methods = json.load(open('apks/json_inputs/locker-fe666e209e094968d3178ecf0cf817164c26d5501ed3cd9a80da786a4a3f3dc4_app_methods_without_class_not_found_error.json')) 
    groupB_methods = json.load(open(json_input_file)) 

    intersection_methods =  list(set(groupA_methods) & set(groupB_methods))
    method_in_groupA_not_in_group_B = list(set(groupA_methods) - set(groupB_methods))
    method_in_groupB_not_in_group_A = list(set(groupB_methods) - set(groupA_methods))
    union_methods = groupB_methods + method_in_groupB_not_in_group_A
  
    print('intersection_methods = ',str(len(intersection_methods)))
    print('method_in_groupA_not_in_group_B = ',str(len(method_in_groupA_not_in_group_B)))
    print('method_in_groupB_not_in_group_A = ',str(len(method_in_groupB_not_in_group_A)))
    print('union_methods = ',str(len(union_methods)))

def clean_json_file(json_input_file,tracer_error_output_file):
    all_methods = json.load(open(json_input_file)) 
    indexes_to_remove = []
    final_methods_datas =  list()
    final_methods =  list()
    method_datas = list()

    methods_candidates = 0
    
    for app_method in all_methods:
        methods_candidates = methods_candidates + 1
        method_data = get_method_data(app_method)
        if(method_data):
            method_datas.append(method_data)
    
    with open(tracer_error_output_file) as fp:
        for cnt, line in enumerate(fp):
            print("Analysing Line {}: {}".format(cnt, line))
            if re.match(r"^(?:\b|(?<=_))Error: java.lang.ClassNotFoundException: Didn't find class(?=\b|_).*$",
                        line):
                print("Error line ", line, '\n split', line.split("\""))
                class_not_found = line.split("\"")[1]
                print(" \n class_not_found name = ", class_not_found)
                index_to_remove = 0
                for method_data in method_datas:
                    method_class_name = method_data['class_name']
                    if (method_class_name == class_not_found):
                        print("method to remove_ ", method_data['method_name'])
                        indexes_to_remove.append(index_to_remove)
                    index_to_remove = index_to_remove + 1 
            else:
                print('not an  ClassNotFoundException error: {} \n'.format(line))
                continue 
    final_methods_data = del_list_indexes(method_datas, indexes_to_remove)
    methods_retained = 0   
    for method_data in final_methods_data:
        methods_retained = methods_retained + 1
        final_methods.append(get_method_signature_from_data(method_data))
    print('method_candidates = ',methods_candidates)
    print('method_retained = ', methods_retained)
    with open(json_input_file, 'w') as outfile:
        json.dump(final_methods, outfile, indent=2)


def split_methods_entries_file():
    #splitting_methods_files 1000 to N
    initial_file_methods = json.load(open('apks/locker-fe666e209e094968d3178ecf0cf817164c26d5501ed3cd9a80da786a4a3f3dc4_app_methods_without_class_not_found_error.json'))
    temp_file_methods = list()
    counter = 0
    for app_method in initial_file_methods:
        counter = counter + 1
        temp_file_methods.append(app_method)
        if((counter % 1000) == 0):
            new_file_path = 'apks/json_inputs/locker-fe666e209e094968d3178ecf0cf817164c26d5501ed3cd9a80da786a4a3f3dc4_app_methods_without_class_not_found_error_' + str(counter) + '_entries.json'
            with open(new_file_path, 'w') as outfile:
                json.dump(temp_file_methods, outfile, indent=2)
                print('file ', new_file_path, ' written')
    print("total entries  ", counter)

def random_split_methods_entries_file(step = 100, max_number_of_methods = 2000):
    initial_file_methods = json.load(open('apks/json_inputs/locker-fe666e209e094968d3178ecf0cf817164c26d5501ed3cd9a80da786a4a3f3dc4_app_methods_without_class_not_found_error.json'))
    max_ = min(max_number_of_methods, len(initial_file_methods))
    for i in range(step, max_, step):
        temp_file_methods =  random.sample(initial_file_methods, i)
        new_file_path = 'apks/json_inputs/locker-fe666e209e094968d3178ecf0cf817164c26d5501ed3cd9a80da786a4a3f3dc4_app_methods_without_class_not_found_error_' + str(i) + '_entries.json'
        with open(new_file_path, 'w') as outfile:
            json.dump(temp_file_methods, outfile, indent=2)
            print('--- >> file ', new_file_path, ' written')
    
    print("--- >> All files written  ")

def random_split_json_methods_file(json_input_file, json_output_folder, gap = 100):
    initial_file_methods = json.load(open(json_input_file))
    max_ =  len(initial_file_methods)
    gap = int(gap)
    #getting the name of the apk
    #app_name = os.path.splitext(os.path.basename(json_input_file))[0]

    for i in range(gap, max_, gap):
        temp_file_methods =  random.sample(initial_file_methods, i)
        new_file_path = json_output_folder + "/"  + str(i) + '_entries.json'
        with open(new_file_path, 'w') as outfile:
            json.dump(temp_file_methods, outfile, indent=2)
            print('--- >> file ', new_file_path, ' written')
    print("--- >> All files written  ")



def find(pattern, path):
    result = []
    for root, dirs, files in os.walk(path):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                result.append(os.path.join(root, name))
    return result

def get_minimal_memory(file, recent_app_detailed_memory): #_if_detailed_data_are_not_avalaible
    print(' --- > parsing result file to get minimal memory: ', file)
    global_memory_usage = 0
    minimal_memory = 0
    with open(file) as fp:
        line = fp.readline()
        while line:
            if ("Uptime:" in line):
                global_memory_usage =  line.split()[1]
                minimal_memory = int(global_memory_usage) - int(recent_app_detailed_memory)
                print("--->Global Memory usage : " + global_memory_usage, ", Minimal memory = " + str(minimal_memory))
                break
            line = fp.readline()
    print(' --- >  minimal memory: ', minimal_memory)
    return minimal_memory


def parse_cpu_result_file(file):
    print(' --- > parsing result file to obtain cpu: ', file)
    cpu_usage = 0.0
    with open(file) as fp:
        line = fp.readline()
        while line:
            cpu_usage =  float(line.split()[8])
            print("---> cpu usage : ", cpu_usage)
            print("---> app name : ", line.split()[11])
            break     
    return cpu_usage

def parse_memory_result_file(file):
    print(' --- > parsing result file to obtain memory: ', file)
    memory_usage = 0
    with open(file) as fp:
        line = fp.readline()
        while line:
            if ("TOTAL:" in line):
                memory_usage =  line.split()[1]
                print("---> Memory usage : ", memory_usage)
                break
            line = fp.readline()
    return memory_usage

def parse_global_memory_result_file(file):
    print(' --- > parsing result file to have global memory: ', file)
    global_memory_usage = 0
    with open(file) as fp:
        line = fp.readline()
        while line:
            if ("Uptime:" in line):
                global_memory_usage =  line.split()[1]
                print("---> Global Memory usage : ", global_memory_usage)
                break
            line = fp.readline()
    print("---> Global Memory usage : ", global_memory_usage)    
    return global_memory_usage

#find('*.txt', '/path/to/dir')

def plot_for_a_certain_number_of_method_v_one(n_methods,moments,
                total_app_memory_by_moment,
                method_correctly_traced_by_moment,
                method_not_correctly_traced_by_moments,
                the_tracer_has_crashed, folder_path):
    plt.figure(figsize=(9, 3))
    ax = plt.subplot(131)
    ax.set_title("App memory")
    ax.bar(list(map(int, moments)), list(map(int, total_app_memory_by_moment)))
    
    ax = plt.subplot(132)
    ax.set_title("Method correctly traced")
    ax.plot(moments, method_correctly_traced_by_moment)
    #ax.scatter(moments, method_correctly_traced_by_moment)
    ax = plt.subplot(133)
    ax.set_title("Method traced with errors")
    ax.plot(moments, method_not_correctly_traced_by_moments)
    plt.subplots_adjust(top=0.8)
    plt.suptitle('General overview of memory consumption, number of methods : ' + str(n_methods) + ",   crash occured ?: " + the_tracer_has_crashed,y=0.98 )
    
    plt.savefig(folder_path + "/plot_v1.pdf")
    plt.show()
    plt.clf()
    plt.cla()
    plt.close()

def plot_for_a_certain_number_of_method_v_two(n_methods,moments,
                total_app_memory_by_moment,
                method_correctly_traced_by_moment,
                method_not_correctly_traced_by_moments,
                the_tracer_has_crashed, folder_path):
    plt.figure(figsize=(9, 3))
    width = 30
    ax = plt.subplot(121)
    ax.set_title("App memory")
    ax.bar(list(map(int, moments)), list(map(int, total_app_memory_by_moment)))
    
    ax = plt.subplot(122)
    ax.set_title("Method traced ")
    p1 = ax.bar(moments, method_correctly_traced_by_moment,   color='#228B22')
    p2 = ax.bar(moments, method_not_correctly_traced_by_moments,  
                bottom=method_not_correctly_traced_by_moments, color='#FF0000')
    plt.legend((p1[0], p2[0]), ('successfull tracing', 'Not successfull tracing'))

    plt.subplots_adjust(top=0.7)
    plt.suptitle('General overview of memory consumption, number of methods : ' + str(n_methods) + ",   crash occured ?: " + the_tracer_has_crashed,y=0.98 )
    
    plt.savefig(folder_path + "/plots/plot_v2.pdf")
    #plt.show()
    plt.clf()
    plt.cla()
    plt.close()



def plot_for_a_certain_number_of_method_for_paper(n_methods,moments,        #modif, ajout de la fonction 
                total_app_memory_by_moment,
                method_correctly_traced_by_moment,
                method_not_correctly_traced_by_moments,
                the_tracer_has_crashed, folder_path):
    #plotting memory evolution
    plt.figure(figsize=(7, 5))
    width = 30
    ax = plt.subplot(111)
    moments_to_plot = list()
    total_app_memory_by_moment_to_plot = list()
    for i in range(13, len(moments)):      #les cinq premières secondes ne comptent pas
            moments_to_plot.append(((float(moments[i]) - 17.5) * 0.3)) # 5 premières secondes avant le tracing + le décompte après le tracing * 0.3
            total_app_memory_by_moment_to_plot.append(total_app_memory_by_moment[i])
    max_error = (len(moments) - 5) * 0.2
    print("moments_to_plot: " + str(moments_to_plot))
    print("memory : " + str(total_app_memory_by_moment_to_plot))
    plus_minus = u'\u00b1'
    ax.set_xlabel("Time in seconds ("+ plus_minus + "0.2 s)") #maximum error " + plus_minus + " " + str(max_error) + " s
    ax.set_ylabel('Memory consumption (KB)')
    plt.ylim(0, 100000)
    plt.xlim(0, 10)
    plt.plot(list (map(float,moments_to_plot)),list (map(int, total_app_memory_by_moment_to_plot)), marker='o', color='green')
    plt.savefig(folder_path + "/plots/memory_plot_for_paper.pdf")
    plt.clf()
    plt.cla()
    plt.close()



    #Plotting detection evolutions
    plt.figure(figsize=(10, 6))       #largeur , hauteur
    width = 30
    ax = plt.subplot(111)
    method_correctly_traced_by_moment_to_plot = list()
    method_not_correctly_traced_by_moments_to_plot = list()
    for i in range(13, len(moments)):    #les cinq premières secondes ne comptent pas
            method_correctly_traced_by_moment_to_plot.append(method_correctly_traced_by_moment[i])
            method_not_correctly_traced_by_moments_to_plot.append(method_not_correctly_traced_by_moments[i])

    print("moments_to_plot: " + str(moments_to_plot))
    print("method_correctly_traced_to_plot : " + str(method_correctly_traced_by_moment_to_plot))
    print("method_not_correctly_traced_to_plot : " + str(method_not_correctly_traced_by_moments_to_plot))
 
    ax.set_xlabel("Time(s)"  , fontsize = 35) #maximum error " + plus_minus + " " + str(max_error) + " s
    ax.set_ylabel('#Intercepted calls (×1000)',  fontsize = 28)

    ax.tick_params(axis='both', which='major', labelsize=35)
    ax.tick_params(axis='both', which='minor', labelsize=35)



    method_correctly_traced_by_moment_to_plot_min = []
    method_not_correctly_traced_by_moments_to_plot_min = []
    for x in method_correctly_traced_by_moment_to_plot:
        alpha = x/1000
        method_correctly_traced_by_moment_to_plot_min.append(alpha)
    for x in method_not_correctly_traced_by_moments_to_plot:
        alpha = x/1000
        method_not_correctly_traced_by_moments_to_plot_min.append(alpha)


    p1 = ax.bar(moments_to_plot, method_correctly_traced_by_moment_to_plot_min,   color='#228B22', edgecolor='black', linewidth=1, width = 0.2)
    p2 = ax.bar(moments_to_plot, method_not_correctly_traced_by_moments_to_plot_min,  
                bottom = method_correctly_traced_by_moment_to_plot_min, color='#E86100', edgecolor='black', linewidth=1, width = 0.2)
  
    plt.rc('legend',fontsize=26) 
    #plt.legend((p1[0], p2[0]), ('Good tracing ', 'Tracing performed with errors') )  
   
    #plt.legend((p1[0], p2[0]), ('Tracing performed without error', 'Tracing performed with some errors'))  
    plt.tight_layout()  
    plt.savefig(folder_path + "/plots/method_traced_plot_for_paper.pdf")
    plt.clf()
    plt.cla()
    plt.close()




def produce_number_of_distinct_methods(json_input_file, experiment_result_folder, n_methods, isOdile = False):   #modif, ajout de la fonction, ajouter l'option -O pour odile
    folder_path = experiment_result_folder + "/"+ str(n_methods) +"_methods_tested"
    list_of_files = os.listdir(folder_path) #list of files in the current directory
    tracer_output_file = ""
    for each_file in list_of_files:
        if each_file.startswith('tracer_output_'):  
            tracer_output_file = folder_path + "/" + each_file
    all_methods = json.load(open(json_input_file)) 
    indexes_to_retain = []
    distinct_methods_datas =  list()
    number_of_distinct_methods = 0
    final_methods =  list()
    method_datas = list()

    methods_candidates = 0
    if not os.path.isdir(folder_path + "/plots"):    #mddif, prise en compte du dossier plots
        os.mkdir(folder_path + "/plots")
    for app_method in all_methods:
        methods_candidates = methods_candidates + 1
        method_data = get_method_data(app_method)
        if(method_data):
            method_datas.append(method_data)
    
    with open(tracer_output_file) as fp:
        if(not isOdile): #frida
            for cnt, line in enumerate(fp):
                #print("Analysing Line {}: {}".format(cnt, line))
            
                if "specified argument types do not match any of" in line:
                    print("Capture line ", line, '\n  method: ', (line.split("(")[0]).split(" ")[1]   )
                    method_name_captured = (line.split("(")[0]).split(" ")[1] 
                    class_name_captured = "null"
                    print(" \n class name = ", class_name_captured , "method name = ", method_name_captured)
                elif  "payload" in line:
                    print("Capture line ", line, '\n split: ', line.split("\""))
                    class_name_captured = line.split("\"")[3]
                    method_name_captured = line.split("\"")[7]
                    print(" \n class name captured = ", class_name_captured , "method name cpatured= ", method_name_captured)
                else:
                    continue 
                print("capture Line {}: {}".format(cnt, line))
                index_detected = 0
                for method_data in method_datas:    
                    candidate_method_name = method_data['method_name']
                    candidate_class_name = method_data['class_name']
                    if (method_name_captured == candidate_method_name) and class_name_captured == "null":   #ici on le pénalise car il ne nous donne pas la classe, du coup on ne considère que la détection d'une seule classe au hasard
                        print("--->method to add ", method_data['method_name'])
                        print("--->Default class name ", method_data['class_name'])
                        indexes_to_retain.append(index_detected)
                        index_detected=index_detected+1
                        break
                    elif (method_name_captured == candidate_method_name) and class_name_captured == candidate_class_name:
                        print("--->method to add ", method_data['method_name'])
                        print("--->Retrieved class name ", method_data['class_name'])
                        indexes_to_retain.append(index_detected)
                        index_detected=index_detected+1
                        break
                    index_detected = index_detected + 1
        else: # is Odile
            print ("----- ----- ----- > Ste Odile")
            find_method = False
            class_name_captured = ""
            for line in fp:
                if not find_method and "descriptor=" in line:
                    #print("Capture line ", line, '\n  ---> retained class name: ', (line.split("=")[1]).split(",")[0]   )
                    class_name_captured = (line.split("=")[1]).split(",")[0] 
                    find_method = True
                    continue
                elif find_method and "methodName=" in line:
                    #print("Capture line ", line, '\n  ---> retained method name: ', (line.split("=")[1])[:-1]  )
                    method_name_captured = (line.split("=")[1])[:-1]
                    if(method_name_captured == "<init>"):
                        method_name_catured = "init"
                    #print(" \n ---> same class name = -" + class_name_captured + "- method name = -"+ method_name_captured + "-")
                    find_method = False
                else:
                    continue 
                index_detected = 0
                #print("We continue the test class name = ", class_name_captured , "method name = ", method_name_captured)
                for method_data in method_datas:    
                    
                    #print("--->json input ", json_input_file)
                    candidate_method_name = method_data['method_name']
                    candidate_class_name = method_data['class_name']
                    if (method_name_captured == candidate_method_name) and candidate_class_name in class_name_captured:
                        #print("--->method to add ", method_data['method_name'])
                        #print("--->Retrieved class name ", method_data['class_name'])
                        indexes_to_retain.append(index_detected)
                        index_detected=index_detected+1
                        break
                    index_detected = index_detected + 1
                continue
                
    distinct_methods_datas = retain_list_indexes(method_datas, indexes_to_retain)
    methods_retained = 0   
    for method_data in distinct_methods_datas:
        methods_retained = methods_retained + 1
        final_methods.append(get_method_signature_from_data(method_data))
    ratio = float(methods_retained)/methods_candidates
    print("index retained", indexes_to_retain)
    print('method_candidates = ',methods_candidates)
    print('method_retained = ', methods_retained)
    print("ratio = ", ratio)
    f = open(folder_path + "/plots/capture_ratio.txt", "w")      #modif, prise en compte du plot
    f.write('method_candidates = ' + str(methods_candidates) + "\nmethod_retained =  " + str(methods_retained) + " \nratio = " + str(ratio))

    captured_methods_file = folder_path + "/plots/captured_methods.json"
    
    with open(captured_methods_file, 'w') as outfile:
        json.dump(final_methods, outfile, indent=2)

def plot_performances_memory_graph_for_paper(baseline_datas , short_path_datas, long_path_datas, experiment_result_folder):
    #plotting memory evolution
    plt.figure(figsize=(7, 5))
    ax = plt.subplot(111)
    
    plus_minus = u'\u00b1'
    #ax.set_xlabel("Time in seconds ("+ plus_minus + "0.2 s)") #maximum error " + plus_minus + " " + str(max_error) + " s
    #ax.set_ylabel('Memory consumption (KB)')
    #plt.ylim(0, 100000)
    #plt.xlim(0, 10)

    baseline_moments_to_plot = list()
    baseline_total_app_memory_by_moment_to_plot = list()
    for i in range(13, len(baseline_datas["moments"])):      #les cinq premières secondes ne comptent pas
            baseline_moments_to_plot.append(((float(baseline_datas["moments"][i]) - 17.5) * 0.3)) # 5 premières secondes avant le tracing + le décompte après le tracing * 0.3
            baseline_total_app_memory_by_moment_to_plot.append(baseline_datas["total_app_memory_by_moment"][i])
    print("baseline_moments_to_plot: " + str(baseline_moments_to_plot))
    print("baseline_total_app_memory_by_moment_to_plot : " + str(baseline_total_app_memory_by_moment_to_plot))


    long_path_moments_to_plot = list()
    long_path_total_app_memory_by_moment_to_plot = list()
    for i in range(13, len(long_path_datas["moments"])):      #les cinq premières secondes ne comptent pas
            long_path_moments_to_plot.append(((float(long_path_datas["moments"][i]) - 17.5) * 0.3)) # 5 premières secondes avant le tracing + le décompte après le tracing * 0.3
            long_path_total_app_memory_by_moment_to_plot.append(long_path_datas["total_app_memory_by_moment"][i])
    print("long_path_moments_to_plot: " + str(long_path_moments_to_plot))
    print("long_path_total_app_memory_by_moment_to_plot : " + str(long_path_total_app_memory_by_moment_to_plot))




    short_path_moments_to_plot = list()
    short_path_total_app_memory_by_moment_to_plot = list()
    for i in range(13, len(short_path_datas["moments"])):      #les cinq premières secondes ne comptent pas
            short_path_moments_to_plot.append(((float(short_path_datas["moments"][i]) - 17.5) * 0.3)) # 5 premières secondes avant le tracing + le décompte après le tracing * 0.3
            short_path_total_app_memory_by_moment_to_plot.append(short_path_datas["total_app_memory_by_moment"][i])
    print("short_path_moments_to_plot: " + str(short_path_moments_to_plot))
    print("short_path_total_app_memory_by_moment_to_plot : " + str(short_path_total_app_memory_by_moment_to_plot))

    ax.tick_params(axis='both', which='major', labelsize=18)
    ax.tick_params(axis='both', which='minor', labelsize=18)

    plt.plot( list (map(float, baseline_moments_to_plot)),list (map(int, baseline_total_app_memory_by_moment_to_plot)),  marker='o', color='#131f02', label = "without Odile")
    plt.plot( list (map(float, short_path_moments_to_plot)),list (map(int, short_path_total_app_memory_by_moment_to_plot)),  marker='o', color='#406302', label = "Odile short path")
    plt.plot( list (map(float, long_path_moments_to_plot)),list (map(int, long_path_total_app_memory_by_moment_to_plot)),  marker='o', color='#2b7ead', label = "Odile long path")
    plt.legend(fontsize=18)



    plt.savefig(experiment_result_folder + "/plots/memory_performance_plot_for_paper.pdf")
    plt.clf()
    plt.cla()
    plt.close()

def produce_memory_performance_datas (folder_path, experiment_type , Odile_experiment = True ):
    # the folder is the result obtained when tracing the app with short or long Odile path or without instrumentalisation
    #     --- ten first files (10) containing initial observations (starting with 0_..., 1_..., ..., 9_....). 
    #         WARNING will consider from 5 to 9 (after app starting) because 0 to 4 (before app starting) are irrevelant 
    #     --- the second files (2*n) contains n observations after starting the app 
    #               (starting with 10_after_sending..., 10_th_tracer_output..., ...)
    #     --- 2 last files, the final tracer output tracer_output_... and the pid file
    #     TOTAL : count = 12+2n => n = ( count - 12 ) / 2 
    print("--- >> folder path " + folder_path)
    onlyfiles = next(os.walk(folder_path))[2] 
    count = len(onlyfiles)
 
    print(' --->> number of files = ', count)
    if (experiment_type == "baseline"):
        n = int((count - 10))
    else:
        n = int((count - 12) / 2)
    print(' --->> number of observation after sent the tracer script,  n = ', n) 
    print( ' --->> we first obtain the entries referring to each testing moment , from 5 to 9 + from 10 to 10+n ')
    after_sending = range(10, 10 + n) 
    moments = [5, 6, 7, 8, 9] + list(after_sending)
    total_app_memory_by_moment = list()
    print(' --- >> We secondly compute memory in 5,6..._after_starting, 10,11..._after_sending looking at line "TOTAL"')  
    minimal_memory = 0
    cached_app_memory = 0
    for i in [5, 6, 7, 8, 9]:
        if (experiment_type == "baseline"):
            file_in_tab = find(str(i) + '_after_sending_*', folder_path)
            print ("baseline path" + file_in_tab[0])
        else:
            file_in_tab = find(str(i) + '_after_starting_app_*', folder_path)
        if file_in_tab[0]:
            app_memory = parse_memory_result_file(file_in_tab[0])
            total_app_memory_by_moment.append(app_memory); cached_app_memory = app_memory
            minimal_memory = minimal_memory if  get_minimal_memory(file_in_tab[0], app_memory) == 0 else get_minimal_memory(file_in_tab[0], app_memory)
            
    for i in after_sending:
        file_in_tab = find(str(i) + '_after_sending_js_methods*', folder_path)
        if file_in_tab[0]:
            app_memory = parse_memory_result_file(file_in_tab[0])
            if app_memory != 0:
                total_app_memory_by_moment.append(app_memory); cached_app_memory = app_memory
                minimal_memory = get_minimal_memory(file_in_tab[0], app_memory)
            else:
                global_app_memory = parse_global_memory_result_file(file_in_tab[0])
                if(global_app_memory != 0  and minimal_memory !=0):
                    app_memory = int(global_app_memory) - minimal_memory
                    total_app_memory_by_moment.append(app_memory); cached_app_memory = app_memory
                else:
                    print("--- >> Maybe the app is closed")
                    total_app_memory_by_moment.append(cached_app_memory)

    print("---> FINAL RESULT for "+ experiment_type +" : ")
    print("---> moments : "); print(*moments, sep = ", ")
    print("---> total_app_memory_by_moment : "); print(*total_app_memory_by_moment, sep = ", ")
    print ("---> generating data file")


    ## getting valuable values of the experiment realized with n methods
    experiment_data = dict()
    experiment_data['moments'] = moments
    experiment_data['total_app_memory_by_moment'] = total_app_memory_by_moment
    experiment_data['max_memory'] = max(map(int,total_app_memory_by_moment))
    return experiment_data

def produce_memory_performance_plot(experiment_result_folder,  Odile_experiment = True):
    baseline_folder_path = experiment_result_folder + "/baseline"
    long_path_folder_path = experiment_result_folder + "/testing_long_path"
    short_path_folder_path = experiment_result_folder + "/testing_short_path"

    if not os.path.isdir(experiment_result_folder + "/plots"):    #mddif, prise en compte du dossier plots
        os.mkdir(experiment_result_folder + "/plots")

    plot_performances_memory_graph_for_paper ( produce_memory_performance_datas(baseline_folder_path,  "baseline", Odile_experiment ),
    produce_memory_performance_datas(long_path_folder_path, "long_path", Odile_experiment ),
    produce_memory_performance_datas(short_path_folder_path, "short_path",  Odile_experiment ), experiment_result_folder)


    


def plot_performances_cpu_graph_for_paper(baseline_datas , short_path_datas, long_path_datas, experiment_result_folder):
    #plotting cpu evolution
    plt.figure(figsize=(10, 6))
    ax = plt.subplot(111)
    
    plus_minus = u'\u00b1'
    ax.set_xlabel("Time (s)", fontsize = 18) # 30 #maximum error " + plus_minus + " " + str(max_error) + " s
    ax.set_ylabel('CPU (%)', fontsize = 18)  # 30
    #plt.ylim(0, 100000)
    #plt.xlim(0, 10)

    baseline_moments_to_plot = list()
    baseline_total_app_cpu_by_moment_to_plot = list()
    for i in range(13, len(baseline_datas["moments"])):      #les cinq premières secondes ne comptent pas
            baseline_moments_to_plot.append(((float(baseline_datas["moments"][i]) - 17.5) * 0.3)) # 5 premières secondes avant le tracing + le décompte après le tracing * 0.3
            baseline_total_app_cpu_by_moment_to_plot.append(baseline_datas["total_app_cpu_by_moment"][i])
    print("baseline_moments_to_plot: " + str(baseline_moments_to_plot))
    print("baseline_total_app_cpu_by_moment_to_plot : " + str(baseline_total_app_cpu_by_moment_to_plot))


    long_path_moments_to_plot = list()
    long_path_total_app_cpu_by_moment_to_plot = list()
    for i in range(13, len(long_path_datas["moments"])):      #les cinq premières secondes ne comptent pas
            long_path_moments_to_plot.append(((float(long_path_datas["moments"][i]) - 17.5) * 0.3)) # 5 premières secondes avant le tracing + le décompte après le tracing * 0.3
            long_path_total_app_cpu_by_moment_to_plot.append(long_path_datas["total_app_cpu_by_moment"][i])
    print("long_path_moments_to_plot: " + str(long_path_moments_to_plot))
    print("long_path_total_app_cpu_by_moment_to_plot : " + str(long_path_total_app_cpu_by_moment_to_plot))

    short_path_moments_to_plot = list()
    short_path_total_app_cpu_by_moment_to_plot = list()
    for i in range(13, len(short_path_datas["moments"])):      #les cinq premières secondes ne comptent pas
            short_path_moments_to_plot.append(((float(short_path_datas["moments"][i]) - 17.5) * 0.3)) # 5 premières secondes avant le tracing + le décompte après le tracing * 0.3
            short_path_total_app_cpu_by_moment_to_plot.append(short_path_datas["total_app_cpu_by_moment"][i])
    print("short_path_moments_to_plot: " + str(short_path_moments_to_plot))
    print("short_path_total_app_cpu_by_moment_to_plot : " + str(short_path_total_app_cpu_by_moment_to_plot))


    ax.tick_params(axis='both', which='major', labelsize=18) #33
    ax.tick_params(axis='both', which='minor', labelsize=18) #33

      
    plt.plot( list (map(float, baseline_moments_to_plot)),list (map(int, baseline_total_app_cpu_by_moment_to_plot)),  marker='o', color='#131f02', label = "without Odile")
    plt.plot( list (map(float, short_path_moments_to_plot)),list (map(int, short_path_total_app_cpu_by_moment_to_plot)),  marker='o', color='#406302', label = "Odile short path")
    plt.plot( list (map(float, long_path_moments_to_plot)),list (map(int, long_path_total_app_cpu_by_moment_to_plot)),  marker='o', color='#2b7ead', label = "Odile long path")
    plt.tight_layout()  
    plt.legend(fontsize=18) #28

    plt.savefig(experiment_result_folder + "/plots/cpu_performance_plot_for_paper.pdf")
    plt.clf()
    plt.cla()
    plt.close()

def produce_cpu_performance_datas (folder_path, experiment_type , Odile_experiment = True ):
    # the folder is the result obtained when tracing the app with short or long Odile path or without instrumentalisation
    #     --- ten first files (10) containing initial observations (starting with 0_..., 1_..., ..., 9_....). 
    #         WARNING will consider from 5 to 9 (after app starting) because 0 to 4 (before app starting) are irrevelant 
    #     --- the second files (2*n) contains n observations after starting the app 
    #               (starting with 10_after_sending..., 10_th_tracer_output..., ...)
    #     --- 2 last files, the final tracer output tracer_output_... and the pid file
    #     TOTAL : count = 12+2n => n = ( count - 12 ) / 2 
    print("--- >> folder path " + folder_path)
    onlyfiles = next(os.walk(folder_path))[2] 
    count = len(onlyfiles)
 
    print(' --->> number of files = ', count)
    if (experiment_type == "baseline"):
        n = int((count - 10))
    else:
        n = int((count - 12) / 2)
    print(' --->> number of observation after sent the tracer script,  n = ', n) 
    print( ' --->> we first obtain the entries referring to each testing moment , from 5 to 9 + from 10 to 10+n ')
    after_sending = range(10, 10 + n) 
    moments = [5, 6, 7, 8, 9] + list(after_sending)
    total_app_cpu_by_moment = list()
    print(' --- >> We secondly compute memory in 5,6..._after_starting, 10,11..._after_sending looking at line "TOTAL"')  
    for i in [5, 6, 7, 8, 9]:
        if (experiment_type == "baseline"):
            file_in_tab = find(str(i) + '_after_sending_*', folder_path)
            print ("baseline path" + file_in_tab[0])
        else:
            file_in_tab = find(str(i) + '_after_starting_app_*', folder_path)
        if file_in_tab[0]:
            app_cpu = parse_cpu_result_file(file_in_tab[0])
            total_app_cpu_by_moment.append(app_cpu); 
            
    for i in after_sending:
        file_in_tab = find(str(i) + '_after_sending_js_methods*', folder_path)
        if file_in_tab[0]:
            app_cpu = parse_cpu_result_file(file_in_tab[0])
            total_app_cpu_by_moment.append(app_cpu); 
               
    print("---> FINAL RESULT for "+ experiment_type +" : ")
    print("---> moments : "); print(*moments, sep = ", ")
    print("---> total_app_cpu_by_moment : "); print(*total_app_cpu_by_moment, sep = ", ")
    print ("---> generating data file")


    ## getting valuable values of the experiment realized with n methods
    experiment_data = dict()
    experiment_data['moments'] = moments
    experiment_data['total_app_cpu_by_moment'] = total_app_cpu_by_moment
    return experiment_data

def produce_cpu_performance_plot(experiment_result_folder,  Odile_experiment = True):
    baseline_folder_path = experiment_result_folder + "/baseline"
    long_path_folder_path = experiment_result_folder + "/testing_long_path"
    short_path_folder_path = experiment_result_folder + "/testing_short_path"

    if not os.path.isdir(experiment_result_folder + "/plots"):    #mddif, prise en compte du dossier plots
        os.mkdir(experiment_result_folder + "/plots")

    plot_performances_cpu_graph_for_paper ( produce_cpu_performance_datas(baseline_folder_path,  "baseline", Odile_experiment ),
    produce_cpu_performance_datas(long_path_folder_path, "long_path", Odile_experiment ),
    produce_cpu_performance_datas(short_path_folder_path, "short_path",  Odile_experiment ), experiment_result_folder)








def produce_plot_entries(experiment_result_folder, n_methods, Odile_experiment = False):
    folder_path = experiment_result_folder + "/"+ str(n_methods) +"_methods_tested"
    # the folder is the result obtained when tracing an a certain number of randomly selected methods with our cobay app
    # the folder contains
    #     --- ten first files (10) containing initial observations (starting with 0_..., 1_..., ..., 9_....). 
    #         WARNING will consider from 5 to 9 (after app starting) because 0 to 4 (before app starting) are irrevelant 
    #     --- the second files (2*n) contains n observations after starting the app 
    #               (starting with 10_after_sending..., 10_th_tracer_output..., ...)
    #     --- 2 last files, the final tracer output tracer_output_... and the pid file
    #     TOTAL : count = 12+2n => n = ( count - 12 ) / 2 
    print("--- >> folder path " + folder_path)
    the_tracer_has_crashed = "NO"
    onlyfiles = next(os.walk(folder_path))[2] 
    count = len(onlyfiles)
    if not os.path.isdir(folder_path + "/plots"):    #mddif, prise en compte du dossier plots
        os.mkdir(folder_path + "/plots")
    print(' --->> number of files = ', count)
    n = int((count - 12) / 2)
    print(' --->> number of observation after sent the tracer script,  n = ', n) 
    print( ' --->> we first obtain the entries referring to each testing moment , from 5 to 9 + from 10 to 10+n ')
    after_sending = range(10, 10 + n) 
    moments = [5, 6, 7, 8, 9] + list(after_sending)
    total_app_memory_by_moment = list()
    method_correctly_traced_by_moment = list()
    method_not_correctly_traced_by_moments = list()
    print(' --- >> We secondly compute memory in 5,6..._after_starting, 10,11..._after_sending looking at line "TOTAL"')  
   
    minimal_memory = 0
    cached_app_memory = 0
    for i in [5, 6, 7, 8, 9]:
        file_in_tab = find(str(i) + '_after_starting_app_*', folder_path)
        if file_in_tab[0]:
            app_memory = parse_memory_result_file(file_in_tab[0])
            total_app_memory_by_moment.append(app_memory); cached_app_memory = app_memory
            minimal_memory = minimal_memory if  get_minimal_memory(file_in_tab[0], app_memory) == 0 else get_minimal_memory(file_in_tab[0], app_memory)
            

   
    for i in after_sending:
        file_in_tab = find(str(i) + '_after_sending_js_methods*', folder_path)
        if file_in_tab[0]:
            app_memory = parse_memory_result_file(file_in_tab[0])
            if app_memory != 0:
                total_app_memory_by_moment.append(app_memory); cached_app_memory = app_memory
                minimal_memory = get_minimal_memory(file_in_tab[0], app_memory)
            else:
                global_app_memory = parse_global_memory_result_file(file_in_tab[0])
                if(global_app_memory != 0  and minimal_memory !=0):
                    app_memory = int(global_app_memory) - minimal_memory
                    total_app_memory_by_moment.append(app_memory); cached_app_memory = app_memory
                else:
                    print("--- >> Maybe the app is closed")
                    total_app_memory_by_moment.append(cached_app_memory)


                       
    print(' --- >> we compute the number of method tracing with error and with payload at any moments')
    for i in [5, 6, 7, 8, 9]:
        method_correctly_traced_by_moment.append(0)
        method_not_correctly_traced_by_moments.append(0)

    for i in after_sending:
        file_in_tab = find(str(i) + '_th_tracer_output_*', folder_path)
        if file_in_tab[0]:
            print(" ---> parsing file ", file_in_tab[0])
            if(Odile_experiment) : 
                print("---> Odile experiments")
                n = open(file_in_tab[0], 'r').read().count("methodName=")
            else:
                print("---> Frida experiments")
                n = open(file_in_tab[0], 'r').read().count("{'payload':")
            method_correctly_traced_by_moment.append(n) 
            print(' ---> method correctly traced = ', n)
            n =  open(file_in_tab[0], 'r').read().count("Error:")
            method_not_correctly_traced_by_moments.append(n)
            print(' ---> method not correctly traced = ', n)
            n = open(file_in_tab[0], 'r').read().count("script is destroyed") 
            if n == 1:
                the_tracer_has_crashed = "YES" 
    
    print("---> FINAL RESULT : ")
    print("---> number of methods : "); print(str(n_methods))
    print("---> moments : "); print(*moments, sep = ", ")
    print("---> total_app_memory_by_moment : "); print(*total_app_memory_by_moment, sep = ", ")
    print("---> method_correctly_traced_by_moment : "); print(*method_correctly_traced_by_moment, sep = ", ")
    print("---> method_not_correctly_traced_by_moments : "); print(*method_not_correctly_traced_by_moments, sep = ", ")
    print("---> crash occured ?  " + the_tracer_has_crashed)
    print ("---> generating data file")

    final_string_data = "#moments     app_memory     method_correctly_traced    method_traced_with_errors"
    for i in range(0, len(moments)):
        final_string_data = final_string_data + "\n" + str(moments[i]) +  "     " + str(total_app_memory_by_moment[i]) + "     " + str(method_correctly_traced_by_moment[i]) +  "     " + str(method_not_correctly_traced_by_moments[i])
     
    f = open(folder_path + "/plots/plot.data", "w")      #modif, prise en compte du plot
    f.write(final_string_data)
    print ("--->  data file content : " + final_string_data)
    
    print("----> plotting results ")
    # evenly sampled time at 200ms intervals
    t = np.arange(0., 5., 0.2)
    #plt.plot(moments, total_app_memory_by_moment, 'r--', moments, method_correctly_traced_by_moment, 'bs', moments, method_not_correctly_traced_by_moments, 'g^')
    # red dashes, blue squares and green triangles
    #plt.plot(t, t, 'r--', t, t**2, 'bs', t, t**3, 'g^')
    
    plot_for_a_certain_number_of_method_v_two(n_methods,moments,
                total_app_memory_by_moment,
                method_correctly_traced_by_moment,
                method_not_correctly_traced_by_moments,
                the_tracer_has_crashed, folder_path)
    plot_for_a_certain_number_of_method_for_paper(n_methods,moments,    #modif, ajout de l'appel 
                total_app_memory_by_moment,
                method_correctly_traced_by_moment,
                method_not_correctly_traced_by_moments,
                the_tracer_has_crashed, folder_path)


    ## getting valuable values of the experiment realized with n methods
    experiment_data = dict()
    experiment_data['number_of_method_tested'] = n_methods
    experiment_data['maximum_app_memory'] = max(list(map(int,total_app_memory_by_moment)))
    experiment_data['number_of_method_correctly_traced'] = max(method_correctly_traced_by_moment)
    experiment_data['number_of_method_not_correctly_traced'] = max(method_not_correctly_traced_by_moments)
    experiment_data['crash_occured'] = the_tracer_has_crashed

    return experiment_data

def yes_no_to_int(yes_or_no):
    return 3 if yes_or_no == "YES" else 2

def get_crash_occurence_sample_of_method_traced_having_value(list_of_yes_no_depending_on_crash_occurences, list_of_number_of_methods_traced, value):
    #This method return a sample of values to realize box plot, 
    # The values returned represent method traced for crash or not
    # The input:
    # The list of crash occurences {YES, NO, NO , YES...} of method tested  sorted according to the number of method traced 
    # The value of method traced for each value before (as a list)
    final_list = list()
    for i in range(0, len(list_of_yes_no_depending_on_crash_occurences)):
        if(list_of_yes_no_depending_on_crash_occurences[i] == value):
            final_list.append(list_of_number_of_methods_traced[i])
    return final_list

def yes_no_to_color(yes_or_no):
    return "#FF8C00" if yes_or_no == "YES" else "#9ACD32"
def plot_general_figure_for_paper(experiment_result_folder, xlabels, box_plot_datas, numbers_of_method_of_all_experiments,
                          total_app_memory_by_number_of_method,  
                        maximum_numbers_of_method_successfully_traced,
                         maximum_numbers_of_method_not_successfully_traced,
                        crash_occurence_yes_no, title, label ):    #modif,  
   
    #plt.figure(figsize=(9, 6))
    #width = 30 
    #ax = plt.subplot(131)
    #ax.set_title("maximum amount of\n memory used by \n the traced mobile app")
    #ax.bar(list(map(int, numbers_of_method_of_all_experiments)), list(map(int, total_app_memory_by_number_of_method)), width)
    #plt.xticks(numbers_of_method_of_all_experiments, xlabels )

    #ax = plt.subplot(132)
    #ax.set_title("Method traced\n successfully (green), \nand with errors (red)")
    #p1 = ax.bar(numbers_of_method_of_all_experiments, maximum_numbers_of_method_successfully_traced, width,  color='#228B22')
    #p2 = ax.bar(numbers_of_method_of_all_experiments, maximum_numbers_of_method_not_successfully_traced, width, 
    #            bottom=maximum_numbers_of_method_successfully_traced, color='#DB9448')
    #plt.legend((p1[0], p2[0]), ('successfull tracing', 'Not successfull tracing'))
    #plt.xticks(numbers_of_method_of_all_experiments, xlabels )
    """
    ax =  plt.subplot(133)
    ax.set_title("Crash occurence (first box) or not (second box)")
    crash_occured_sample = get_crash_occurence_sample_of_method_traced_having_value(crash_occurence_yes_no, box_plot_datas, "YES")
    crash_not_occured_sample = get_crash_occurence_sample_of_method_traced_having_value(crash_occurence_yes_no, box_plot_datas, "NO")
    print("crash occured " + str(crash_occured_sample))
    print("crash not occured " + str(crash_occured_sample))
    data = [crash_occured_sample, crash_not_occured_sample] 
    ax.boxplot(data, notch=True)

    plt.subplots_adjust(top=0.8)    
    plt.suptitle(title ,y=0.98 )
    plt.savefig(experiment_result_folder + "/general_plot_"+ label +".pdf")
    plt.clf()
    plt.cla()
    plt.close()
   """

    baseline_datas = produce_memory_performance_datas(experiment_result_folder + "/baseline",  "baseline", True )
    baseline_max_memory = baseline_datas ['max_memory']/1000
    #plotting memory evolution
    plt.figure(figsize=(10, 6))
    ax = plt.subplot(111)
    ax.set_xlabel("#Methods to be traced", fontsize = 18) #30 
    ax.set_ylabel('Memory consumption (MB)', fontsize = 18) #28
    list_with_big_numbers = list(map(float, total_app_memory_by_number_of_method))
    numbers_of_method_of_all_experiments_to_plot = list (map(float,numbers_of_method_of_all_experiments))

    list_with_short_numbers =  []
    indices_to_remove = []
    current_indice = 0
    for x in list_with_big_numbers:
        if(x<100000):
            alpha = x/1000
            list_with_short_numbers.append(alpha)
        else:     
            indices_to_remove.append(current_indice)
            print("---------> number_of_method_removed = " , str(numbers_of_method_of_all_experiments_to_plot[current_indice]))
            print("-------->  memory = " , str(x) )
            

        current_indice = current_indice + 1
    
    numbers_of_method_of_all_experiments_to_plot = [i for j, i in enumerate(numbers_of_method_of_all_experiments_to_plot) if j not in indices_to_remove]
    print("indices removed = " ) ;  print(*indices_to_remove, sep = ",") 


##############
    baseline_memory_line_to_plot = list()
    for i in range(0, len(numbers_of_method_of_all_experiments_to_plot)):      
        baseline_memory_line_to_plot.append(baseline_max_memory) 
           
    print("##### ##### ##### baseline_memory_line_to_plot: " + str(baseline_memory_line_to_plot))

    ax.tick_params(axis='both', which='major', labelsize= 18) #35
    ax.tick_params(axis='both', which='minor', labelsize= 18) #35

    plt.plot( numbers_of_method_of_all_experiments_to_plot,list (map(int, baseline_memory_line_to_plot)),  marker='o', color='#131f02', label = "without Odile")
    plt.plot(numbers_of_method_of_all_experiments_to_plot, list_with_short_numbers, marker='o', color='#2B9AB5', label = "with Odile")
    plt.tight_layout()
    plt.legend(fontsize=18) #28
#############

    plt.savefig(experiment_result_folder + "/plots/"+ label + "__memory_plot_for_paper.pdf")
    plt.clf()
    plt.cla()
    plt.close()

     #plotting detection evolution
    plt.figure(figsize=(10, 6))
    width = 30
    ax = plt.subplot(111)
    ax.set_xlabel("#Methods to be traced", fontsize = 18) #30
    ax.set_ylabel('#Intercepted calls (×1000)', fontsize = 18) #28
    ax.tick_params(axis='both', which='major', labelsize= 18) #35
    ax.tick_params(axis='both', which='minor', labelsize= 18) #35


    maximum_numbers_of_method_successfully_traced_min = []
    maximum_numbers_of_method_not_successfully_traced_min = []
    for x in maximum_numbers_of_method_successfully_traced:
        alpha = x/1000
        maximum_numbers_of_method_successfully_traced_min.append(alpha)
    for x in maximum_numbers_of_method_not_successfully_traced:
        alpha = x/1000
        maximum_numbers_of_method_not_successfully_traced_min.append(alpha)



    p1 = ax.bar(numbers_of_method_of_all_experiments, maximum_numbers_of_method_successfully_traced_min, color='#228B22', width = 65)
    p2 = ax.bar(numbers_of_method_of_all_experiments, maximum_numbers_of_method_not_successfully_traced_min,
                bottom=maximum_numbers_of_method_successfully_traced_min, color='#E86100',  width = 65)
    #plt.legend((p1[0], p2[0]), ('Tracing performed without error', 'Tracing performed with some errors'))  
    zipped_lists = zip(maximum_numbers_of_method_successfully_traced, maximum_numbers_of_method_not_successfully_traced)
    sum_list = [x + y for (x, y) in zipped_lists]
    m_ = int(sum(sum_list) / len(sum_list))
    #ax.axhline(y=m_, color='gray', linestyle='--',  label = "mean = " + str(m_)) # label = "mean = " + str(m_) 
    
    
    #plt.xticks(np.arange(min(numbers_of_method_of_all_experiments), max(numbers_of_method_of_all_experiments), 1000))
    plt.rc('legend',fontsize=18) #28  
    plt.legend((p1[0], p2[0]), ('Tracing performed without error', 'Tracing performed with some errors') )  
    plt.tight_layout()  



    plt.savefig(experiment_result_folder + "/plots/"+ label + "__detection_plot_for_paper.pdf")
    plt.clf()
    plt.cla()
    plt.close()

    """
    #Plotting detection evolutions
    plt.figure(figsize=(7, 5))
    width = 30
    ax = plt.subplot(111)
    method_correctly_traced_by_moment_to_plot = list()
    method_not_correctly_traced_by_moments_to_plot = list()
    for i in range(5, len(moments)):    #les cinq premières secondes ne comptent pas
            method_correctly_traced_by_moment_to_plot.append(method_correctly_traced_by_moment[i])
            method_not_correctly_traced_by_moments_to_plot.append(method_not_correctly_traced_by_moments[i])

    print("moments_to_plot: " + str(moments_to_plot))
    print("method_correctly_traced_to_plot : " + str(method_correctly_traced_by_moment_to_plot))
    print("method_not_correctly_traced_to_plot : " + str(method_not_correctly_traced_by_moments_to_plot))
    ax.set_xlabel("Time in seconds ("+ plus_minus + "0.2 s)") #maximum error " + plus_minus + " " + str(max_error) + " s
    ax.set_ylabel('Number of methods')

    p1 = ax.bar(moments_to_plot, method_correctly_traced_by_moment_to_plot,   color='#228B22')
    p2 = ax.bar(moments_to_plot, method_not_correctly_traced_by_moments_to_plot,  
                bottom = method_correctly_traced_by_moment_to_plot, color='#DB9448')
    plt.legend((p1[0], p2[0]), ('Tracing performed without error', 'Tracing performed with some errors'))    
    plt.savefig(folder_path + "/plots/method_traced_plot_for_paper.pdf")
    plt.clf()
    plt.cla()
    plt.close()
    """






def plot_general_figure(experiment_result_folder, xlabels, box_plot_datas, numbers_of_method_of_all_experiments,
                          total_app_memory_by_number_of_method,  
                        maximum_numbers_of_method_successfully_traced,
                         maximum_numbers_of_method_not_successfully_traced,
                        crash_occurence_yes_no, title, label ):

    #plt.plot(xs, values)
    #plt.xticks(xs, days)
    plt.figure(figsize=(9, 6))
    width = 30 
    ax = plt.subplot(131)
    ax.set_title("maximum amount of\n memory used by \n the traced mobile app")
    ax.bar(list(map(int, numbers_of_method_of_all_experiments)), list(map(int, total_app_memory_by_number_of_method)), width)
    plt.xticks(numbers_of_method_of_all_experiments, xlabels )
    #ax.set_xticklabels(numbers_of_method_of_all_experiments)

    ax = plt.subplot(132)
    ax.set_title("Method traced\n successfully (green), \nand with errors (red)")
    p1 = ax.bar(numbers_of_method_of_all_experiments, maximum_numbers_of_method_successfully_traced, width,  color='#228B22')
    p2 = ax.bar(numbers_of_method_of_all_experiments, maximum_numbers_of_method_not_successfully_traced, width, 
                bottom=maximum_numbers_of_method_successfully_traced, color='#FF0000')
    plt.legend((p1[0], p2[0]), ('successfull tracing', 'Not successfull tracing'))
    plt.xticks(numbers_of_method_of_all_experiments, xlabels )


    
    #ax = plt.subplot(133)
    #ax.set_title("Crash occured\n (darkorange = yes),\n (yellowgreen = no)  ")
    #data = {'x_axis': numbers_of_method_of_all_experiments,
    #    'y_axis':  list(map(yes_no_to_int, crash_occurence_yes_no)),
    #    'color':  list(map(yes_no_to_color, crash_occurence_yes_no))}
    #ax.scatter('x_axis', 'y_axis', c='color', data=data)
    #plt.xticks(numbers_of_method_of_all_experiments, xlabels )

    
    ax =  plt.subplot(133)
    ax.set_title("Crash occurence (first box) or not (second box)")
    crash_occured_sample = get_crash_occurence_sample_of_method_traced_having_value(crash_occurence_yes_no, box_plot_datas, "YES")
    crash_not_occured_sample = get_crash_occurence_sample_of_method_traced_having_value(crash_occurence_yes_no, box_plot_datas, "NO")
    print("crash occured " + str(crash_occured_sample))
    print("crash not occured " + str(crash_occured_sample))
    data = [crash_occured_sample, crash_not_occured_sample] 
    ax.boxplot(data, notch=True)
    
    



    #ax.set_xticklabels(numbers_of_method_of_all_experiments)


    plt.subplots_adjust(top=0.8)    
    plt.suptitle(title ,y=0.98 )
    plt.savefig(experiment_result_folder + "/plots/general_plot_"+ label +".pdf")
    #plt.show()
    plt.clf()
    plt.cla()
    plt.close()



def produce_summary_plot(experiment_result_folder, from_ = 100 ,to_ = 15000 ,step_ = 100, Odile_experiment = False):
    plots_data_for_all_apps_summary_plot = dict()
    experiment_datas = list()
    print ("---> Building the list of dictionnaries")
    for n_methods in range(from_, to_ ,step_):
        experiment_datas.append(produce_plot_entries(experiment_result_folder, n_methods, Odile_experiment))
    # first plot, ordered according to the number of methods tested

    if not os.path.isdir(experiment_result_folder + "/plots"):    #mddif, prise en compte du dossier plots
        os.mkdir(experiment_result_folder + "/plots")
    print ("---> Retriving datas  ordered according to the number of methods tested")
    
    numbers_of_method_of_all_experiments = list(map(lambda rec: rec.get('number_of_method_tested'), experiment_datas))
    total_app_memory_by_number_of_method = list(map(lambda rec: rec.get('maximum_app_memory'), experiment_datas))
    maximum_numbers_of_method_successfully_traced =  list(map(lambda rec: rec.get('number_of_method_correctly_traced'), experiment_datas))
    maximum_numbers_of_method_not_successfully_traced = list(map(lambda rec: rec.get('number_of_method_not_correctly_traced'), experiment_datas))
    crash_occurence_yes_no = list(map(lambda rec: rec.get('crash_occured'), experiment_datas))
    
    print ("---> Range of number of methods : ");  print(*numbers_of_method_of_all_experiments, sep = ", ")
    print ("---> Range of number of methods : ");  print(*numbers_of_method_of_all_experiments, sep = ", ")


    plots_data_for_all_apps_summary_plot["crash_occured_sample_according_to_methods_tested"] = (
        get_crash_occurence_sample_of_method_traced_having_value(crash_occurence_yes_no, numbers_of_method_of_all_experiments, "YES"))
    plots_data_for_all_apps_summary_plot["crash_not_occured_sample_according_to_methods_tested"] = (
        get_crash_occurence_sample_of_method_traced_having_value(crash_occurence_yes_no, numbers_of_method_of_all_experiments, "NO"))

    plot_general_figure(experiment_result_folder, numbers_of_method_of_all_experiments, numbers_of_method_of_all_experiments,
                        numbers_of_method_of_all_experiments,
                        total_app_memory_by_number_of_method,  
                        maximum_numbers_of_method_successfully_traced,
                         maximum_numbers_of_method_not_successfully_traced,
                        crash_occurence_yes_no,'General overview of memory, successful tracing,\n and crash occurences  according to the number of methods tested',
                        "ordered_according_to_number_of_methods_tested")

    plot_general_figure_for_paper(experiment_result_folder, numbers_of_method_of_all_experiments, numbers_of_method_of_all_experiments,
                    numbers_of_method_of_all_experiments,
                    total_app_memory_by_number_of_method,  
                    maximum_numbers_of_method_successfully_traced,
                        maximum_numbers_of_method_not_successfully_traced,
                    crash_occurence_yes_no,'General overview of memory, successful tracing,\n and crash occurences  according to the number of methods tested',
                    "ordered_according_to_number_of_methods_tested")   #modif,



    # second plot, ordered according to the number of methods traced 
    print ("---> Retriving datas  ordered according to the number of methods traced (not tested)")
    maximum_numbers_of_method_traced = [a + b for a, b in zip(maximum_numbers_of_method_successfully_traced, maximum_numbers_of_method_not_successfully_traced)]

    print ("---> Retriving permutation")
    L = [ (maximum_numbers_of_method_traced[i],i) for i in range(0,len(maximum_numbers_of_method_traced)) ]
    L.sort()
    sorted_maximum_numbers_of_method_traced,permutation = zip(*L)
    print ("---> Applying permutation")

    sorted_numbers_of_method_of_all_experiments = [numbers_of_method_of_all_experiments[i] for i in permutation]
    sorted_total_app_memory_by_number_of_method =  [ total_app_memory_by_number_of_method[i] for i in permutation]
    sorted_maximum_numbers_of_method_successfully_traced = [ maximum_numbers_of_method_successfully_traced[i] for i in permutation]
    sorted_maximum_numbers_of_method_not_successfully_traced = [maximum_numbers_of_method_not_successfully_traced[i] for i in permutation]
    sorted_crash_occurence_yes_no = [ crash_occurence_yes_no[i] for i in permutation]

    plots_data_for_all_apps_summary_plot["crash_occured_sample_according_to_methods_traced"] = (
        get_crash_occurence_sample_of_method_traced_having_value(sorted_crash_occurence_yes_no, sorted_maximum_numbers_of_method_traced, "YES"))
    plots_data_for_all_apps_summary_plot["crash_not_occured_sample_according_to_methods_traced"] = (
        get_crash_occurence_sample_of_method_traced_having_value(sorted_crash_occurence_yes_no, sorted_maximum_numbers_of_method_traced, "NO"))

    plot_general_figure(experiment_result_folder, sorted_numbers_of_method_of_all_experiments, sorted_maximum_numbers_of_method_traced, #sorted_numbers_of_method_of_all_experiments,
                       numbers_of_method_of_all_experiments,
                          sorted_total_app_memory_by_number_of_method,  
                        sorted_maximum_numbers_of_method_successfully_traced,
                         sorted_maximum_numbers_of_method_not_successfully_traced,
                        sorted_crash_occurence_yes_no,'General overview of memory, successful tracing,\n and crash occurences  according to the number of methods traced',
                        "ordered_according_to_number_of_methods_traced" )

    # third  plot, ordered according to the memory usedplt.clf()
    plt.cla()
    plt.close()
    print ("---> Retriving datas   ordered according to the memory used")

    print ("---> Retriving permutation")
    L = [ (total_app_memory_by_number_of_method[i],i) for i in range(0,len(total_app_memory_by_number_of_method)) ]
    L.sort()
    sorted_total_app_memory_by_number_of_method,permutation = zip(*L)
    print ("---> Applying permutation")

    sorted_numbers_of_method_of_all_experiments = [numbers_of_method_of_all_experiments[i] for i in permutation]
    sorted_total_app_memory_by_number_of_method =  [ total_app_memory_by_number_of_method[i] for i in permutation]
    sorted_maximum_numbers_of_method_successfully_traced = [ maximum_numbers_of_method_successfully_traced[i] for i in permutation]
    sorted_maximum_numbers_of_method_not_successfully_traced = [maximum_numbers_of_method_not_successfully_traced[i] for i in permutation]
    sorted_crash_occurence_yes_no = [ crash_occurence_yes_no[i] for i in permutation]


    plots_data_for_all_apps_summary_plot["crash_occured_sample_according_to_memory_used"] = (
        get_crash_occurence_sample_of_method_traced_having_value(sorted_crash_occurence_yes_no, sorted_total_app_memory_by_number_of_method, "YES"))
    plots_data_for_all_apps_summary_plot["crash_not_occured_sample_according_to_memory_used"] = (
        get_crash_occurence_sample_of_method_traced_having_value(sorted_crash_occurence_yes_no, sorted_total_app_memory_by_number_of_method, "NO"))

    plot_general_figure(experiment_result_folder, sorted_numbers_of_method_of_all_experiments, sorted_total_app_memory_by_number_of_method,
                       numbers_of_method_of_all_experiments,
                          sorted_total_app_memory_by_number_of_method,  
                        sorted_maximum_numbers_of_method_successfully_traced,
                         sorted_maximum_numbers_of_method_not_successfully_traced,
                        sorted_crash_occurence_yes_no,'General overview of memory, successful tracing,\n and crash occurences ordered according to the memory used',
                         "ordered_according_to_memory_used")

    return plots_data_for_all_apps_summary_plot
    #plt.show()
 

def produce_all_apks_summary_plot(experiment_result_folder, gap = 100,  Odile_experiment = False):
    all_apps_experiments_data = list()
    apps_experiments_stats = list()
    labels = list()
    print ("---> Building the list of dictionnaries of all apps, gap  = " + str(gap))
    
    subfolders = [ f.path for f in os.scandir(experiment_result_folder) if f.is_dir() ]
    for app_directory in subfolders:
        app_file_name_without_extension = os.path.basename(app_directory)
        print ("---> Building the list of dictionnaries of apk: " + app_file_name_without_extension)
        
        number_of_tests = len([ f.name for f in os.scandir(app_directory) if f.is_dir() ]) - 2 #modif added -2,  for folders baseline and plot 
        print ("---> Number of test : " + str(number_of_tests))
        max_number_of_methods = number_of_tests * gap
        current_app_experiment_data = produce_summary_plot(app_directory, gap, max_number_of_methods, gap, Odile_experiment)
        current_app_experiment_data["app_file_name"] = app_file_name_without_extension
        all_apps_experiments_data.append(current_app_experiment_data)


    for app_row_data in all_apps_experiments_data:
        app_label_as_array = list()
        app_label_as_array.append(app_row_data["app_file_name"])
        #app_label_as_array.append("")
        labels.append(app_row_data["app_file_name"])
        app_stats_data = dict()
        app_stats_data["crash_occured_sample_according_to_methods_tested"] = (
            cbook.boxplot_stats(app_row_data["crash_occured_sample_according_to_methods_tested"] , labels=app_label_as_array, bootstrap=10000))[0]
        app_stats_data["crash_not_occured_sample_according_to_methods_tested"] = (
            cbook.boxplot_stats(app_row_data["crash_not_occured_sample_according_to_methods_tested"] , labels=app_label_as_array, bootstrap=10000))[0]
        app_stats_data["crash_occured_sample_according_to_methods_traced"] = (
            cbook.boxplot_stats(app_row_data["crash_occured_sample_according_to_methods_traced"] , labels=app_label_as_array, bootstrap=10000))[0]
        app_stats_data["crash_not_occured_sample_according_to_methods_traced"] = (
            cbook.boxplot_stats(app_row_data["crash_not_occured_sample_according_to_methods_traced"] , labels=app_label_as_array, bootstrap=10000))[0]
        app_stats_data["crash_occured_sample_according_to_memory_used"] = (
            cbook.boxplot_stats(app_row_data["crash_occured_sample_according_to_memory_used"] , labels=app_label_as_array, bootstrap=10000))[0]
        app_stats_data["crash_not_occured_sample_according_to_memory_used"] = (
            cbook.boxplot_stats(app_row_data["crash_not_occured_sample_according_to_memory_used"] , labels=app_label_as_array, bootstrap=10000))[0]
        print("current app stats : " + str(app_stats_data))
        apps_experiments_stats.append(app_stats_data)


    # finally we have something like
    # Labels ["app 1", "app 2", ....]
    # apps_experiments_stats [
    #       (app1_stats) [
    #               "case 1" : {stat in case one, means, median.....}     
    #               "case 2" : {stat in case two, means, median.....}  
    #                   ...
    #               "case 6" : {stat in case six, ....}      
    #       ],
    #       (app2_stats) [
    #               "case 1" : {stat in case one, means, median.....}     
    #               "case 2" : {stat in case two, means, median.....}  
    #                   ...
    #               "case 6" : {stat in case six, ....}      
    #       ],
    #       .... M app 
    # ]
    # But we want to plot six graphs, corresponding to six cases, each of theses graphs having M box plots corresponding to M applications 
    # so we have to extract the data above.
    #    
    print ("---> Total stats app datas ! \n\n\n" +  str(apps_experiments_stats) )
    plot_stats_of_crash_occured_sample_according_to_methods_tested = (
        list(map(lambda rec: rec.get('crash_occured_sample_according_to_methods_tested'), apps_experiments_stats)))
    plot_stats_of_crash_not_occured_sample_according_to_methods_tested = (
        list(map(lambda rec: rec.get('crash_not_occured_sample_according_to_methods_tested'), apps_experiments_stats)))
    plot_stats_of_crash_occured_sample_according_to_methods_traced = (
        list(map(lambda rec: rec.get('crash_occured_sample_according_to_methods_traced'), apps_experiments_stats)))
    plot_stats_of_crash_not_occured_sample_according_to_methods_traced = (
        list(map(lambda rec: rec.get('crash_not_occured_sample_according_to_methods_traced'), apps_experiments_stats)))
    plot_stats_of_crash_occured_sample_according_to_memory_used = (
        list(map(lambda rec: rec.get('crash_occured_sample_according_to_memory_used'), apps_experiments_stats)))
    plot_stats_of_crash_not_occured_sample_according_to_memory_used = (
        list(map(lambda rec: rec.get('crash_not_occured_sample_according_to_memory_used'), apps_experiments_stats)))
    
    print ("---> Plotting the results ! \n\n\n" +  str(plot_stats_of_crash_occured_sample_according_to_methods_tested) )


    fs = 10  # fontsize

    ###############################################################################
    # Demonstrate how to toggle the display of different elements:

    fig, axs = plt.subplots(nrows=1, ncols=2, figsize=(4, 3), sharey=True)
    axs[0].bxp(plot_stats_of_crash_occured_sample_according_to_methods_tested, showfliers=False)
    axs[0].set_title('Crash occurence on all tested apps ', fontsize=fs)

    axs[1].bxp(plot_stats_of_crash_not_occured_sample_according_to_methods_tested, showfliers=False)
    axs[1].set_title('Tests without crashs on all tested apps' , fontsize=fs)
    
    for ax in axs.flat:
        ax.set_xticklabels([])
    plt.subplots_adjust(top=0.8)    
    plt.suptitle("Test results according to methods tested" ,y=0.98 )
    plt.savefig(experiment_result_folder + "/general_plot_for_methods_tested.pdf")
    #plt.show()


    fig, axs = plt.subplots(nrows=1, ncols=2, figsize=(4, 3), sharey=True)
    axs[0].bxp(plot_stats_of_crash_occured_sample_according_to_methods_traced, showfliers=False)
    axs[0].set_title('Crash occurence on all tested apps ', fontsize=fs)

    axs[1].bxp(plot_stats_of_crash_not_occured_sample_according_to_methods_traced, showfliers=False)
    tufte_title = 'Tests without crashs on all tested apps '
    axs[1].set_title(tufte_title, fontsize=fs)
    for ax in axs.flat:
        ax.set_xticklabels([])
    plt.subplots_adjust(top=0.8)    
    plt.suptitle("Test results according to methods traced" ,y=0.98 )
    plt.savefig(experiment_result_folder + "/general_plot_for_methods_traced.pdf")
    #plt.show()

    fig, axs = plt.subplots(nrows=1, ncols=2, figsize=(4, 3), sharey=True)
    axs[0].bxp(plot_stats_of_crash_occured_sample_according_to_memory_used, showfliers=False)
    axs[0].set_title('Crash occurence on all tested  apps', fontsize=fs)

    axs[1].bxp(plot_stats_of_crash_not_occured_sample_according_to_memory_used, showfliers=False)
    axs[1].set_title('Tests without crashs on all tested apps ', fontsize=fs)
    for ax in axs.flat:
        ax.set_xticklabels([])
    plt.subplots_adjust(top=0.8)    
    plt.suptitle("Test results according to memory used" ,y=0.98 )
    plt.savefig(experiment_result_folder + "/general_plot_for_memory_used.pdf")
    plt.show()
    #for ax in axs.flat:
        ##ax.set_yscale('log')
        ##ax.set_yticklabels([])

    #fig.subplots_adjust(hspace=0.4)
    #plt.show()
    










def deduplicate_json_file(json_input_file):
    app_methods = json.load(open(json_input_file))
    print("***** List size before removing duplicates : " + str(len(app_methods)))
    app_methods = list(dict.fromkeys(app_methods))
    print("***** List size after removing duplicates : " + str(len(app_methods)))
    with open(json_input_file, 'w') as outfile:
        json.dump(app_methods, outfile, indent=2)



def run(argv):
    n_methods = 7000
    deduplicate = False
    clean = False
    intersect_methods =  False
    split_methods = False
    generate_global_plots = False
    generate_partial_results = False    #modif, renommage
    compute_distinct_traced_methods = False #modif, simple ajout
    plot_union = False
    Odile_experiment = False
    performance_experiments = False
    memory_performance_experiments = False
    cpu_performance_experiments = False
    #to continue , add option -s split  in expes_result_overview_tool to randomize the -f json_input_file_path, split in 
	# many files according to the gap -g and generate them -o in the OUTPUT_JSON_FOLDER

	

    try:
        opts, args = getopt.getopt(argv,"han:x:df:ce:isg:o:m:uODPMC",
                ["app_path","n_methods=","experiment_result_folder=","deduplicate","json_input_file=","clean",
                    "error_output_file=","intersect","split","gap=","json_output_folder","max_methods_tested=","union","Odile_experiment",
                    "compute_distinct_traced_methods","performance_experiments","memory_performance_experiments", "cpu_performance_experiments"])
    except getopt.GetoptError:
        print('expes_result_overview_tool.py -a <apk_path> -n <n_methods> -x <experiment_result_folder> -d <deduplicate> -f <json_input_file>'
         +'\n -e <error_output_file> -i (if you want to intersect) -s (if you want to split) -g <the gap> ' 
        +'\n -o <json_output_folder> -m <max_methods_tested> -u (if you want plot union) -O <To mention that it is for Odile experiments> -D <compute_distinct_traced_methods>'
        +'\n -P <performance_experiments> -M <memory_performance_experiments> -C <memory_performance_experiments>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('expes_result_overview_tool.py -a apk_path -n <n_methods> ')
            sys.exit()
        elif opt in ("-n", "--n_methods"):
            generate_partial_results = True
            n_methods = arg
        elif opt in ("-m", "--max_methods_tested"):
            generate_global_plots = True
            max_methods_tested = arg
        elif opt in ("-x", "--experiment_result_folder"):
            experiment_result_folder = arg
        elif opt in ("-a", "--apk_path"):
            apk_path = arg
        elif opt in ("-d", "--deduplicate"):
            deduplicate = True
        elif opt in ("-f", "--json_input_file"):
            json_input_file = arg
        elif opt in ("-c", "--clean"):
            clean = True
        elif opt in ("-e", "--error_output_file"):
            tracer_error_output_file = arg 
        elif opt in ("-i", "--intersect_methods"):
            intersect_methods = True  
        elif opt  in ("-s", "--split"):
            split_methods = True     
        elif opt in ("-g", "--gap"):
            gap = arg  
        elif opt in ("-o", "--json_output_folder"):
            json_output_folder = arg    
        elif opt in ("-u", "--plot_union"):
            plot_union = True
        elif opt in ("-O", "--Odile_experiment"):
            Odile_experiment = True
        elif opt in ("-D", "--compute_distinct_traced_methods"): #modif, simple ajout
            compute_distinct_traced_methods = True
        elif opt in ("-P", "--performance_experiments"): #performance experiments
            performance_experiments = True
        elif opt in ("-M", "--memory_performance_experiments"): #performance experiments
            memory_performance_experiments = True       
        elif opt in ("-C", "--cpu_performance_experiments"): #performance experiments
            cpu_performance_experiments = True       



    if(performance_experiments): 
        print(" ***** ***** Generating global performance  plots : " )
        if(memory_performance_experiments):  #modif, simple ajout du if
            print(" ***** ***** For Memory Performances: " )
            print(" ***** ***** memory_experiment_result_folder: " + experiment_result_folder)
            produce_memory_performance_plot(experiment_result_folder, Odile_experiment)
            return None
        if(cpu_performance_experiments):  #modif, simple ajout du if
            print(" ***** ***** For CPU Performances: " )
            print(" ***** ***** cpu_experiment_result_folder: " + experiment_result_folder)
            produce_cpu_performance_plot(experiment_result_folder, Odile_experiment)
            return None
      
    if(deduplicate):
        print(" ***** *****  Json input file :" + json_input_file)
        deduplicate_json_file(json_input_file)
        return None
    if(clean):
        print(" ***** *****  Json input file :" + json_input_file)
        print(" ***** *****  error output file :" + tracer_error_output_file)
        clean_json_file(json_input_file,tracer_error_output_file)
        return None
    if(intersect_methods):
        print(" ***** *****  Json input file :" + json_input_file)
        intersect_methods_(json_input_file)
        return None
    if(split_methods):
        print(" ***** *****  Splitting Json input file :" + json_input_file)
        print(" ***** *****  Json output folder :" + json_output_folder)
        random_split_json_methods_file(json_input_file, json_output_folder, gap)
        return None
    if(generate_partial_results):
        if(compute_distinct_traced_methods):  #modif, simple ajout du if
            print(" ***** ***** Generating distinct methods traced: " )
            print(" ***** ***** experiment_result_folder: " + experiment_result_folder)
            print(" ***** ***** n_method: " + n_methods)
            print(" ***** *****  Json input file :" + json_input_file)
            produce_number_of_distinct_methods(json_input_file, experiment_result_folder, n_methods, Odile_experiment)
            return None
        print(" ***** ***** Generating partial plots: " )
        print(" ***** ***** experiment_result_folder: " + experiment_result_folder)
        print(" ***** ***** n_method: " + n_methods)
        produce_plot_entries(experiment_result_folder, n_methods, Odile_experiment)
        return None
    if(generate_global_plots): 
        print(" ***** ***** Generating global plots of one app: " )
        print(" ***** ***** app experiment_result_folder: " + experiment_result_folder)
        print(" ***** ***** max_method_tested: " + max_methods_tested)
        print(" ***** ***** gap: " + gap)
        produce_summary_plot(experiment_result_folder, int(gap), int(max_methods_tested), int(gap), Odile_experiment)
        return None
    if(plot_union):    
        print(" ***** ***** Generating global plots of all apps:  " )
        print(" ***** ***** experiment_result_folder: " + experiment_result_folder)
        print(" ***** ***** gap: " + gap)
        produce_all_apks_summary_plot(experiment_result_folder, int(gap), Odile_experiment)
        return None



    length_apk_path_dot = len(apk_path.split('.'))
    app_name_without_extension = apk_path.split('.')[length_apk_path_dot-2]
    print('apk_name = ', app_name_without_extension)
    print ('n_methods  is ', n_methods)
    global methods_hooks
    patterns = [
    {
        "class_name": "*",
        "method_names": ['*']
    },]
    
    return None

    #generate_valid_methods()
    #split_methods_entries_file()
    #random_split_methods_entries_file(100,10000)
    #produce_plot_entries(n_methods)
    #produce_summary_plot(app_name_without_extension, 100, 5000, 100)



if __name__ == "__main__":
    run(sys.argv[1:])
