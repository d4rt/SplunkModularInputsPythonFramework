'''
Tshark Modular Input Script

Copyright (C) 2012-2014 Splunk, Inc.
All Rights Reserved
'''

import sys, logging, os, time, subprocess, re
import xml.dom.minidom, xml.sax.saxutils

# set up logging
logging.root
logging.root.setLevel(logging.INFO)
formatter = logging.Formatter('%(levelname)s %(message)s')

# if no arguments are supplied, send output to stderr

handler = logging.StreamHandler()
handler.setFormatter(formatter)
logging.root.addHandler(handler)

TSHAR_OUTPUT_HANDLER_INSTANCE = None

SCHEME = """<scheme>
    <title>tshark</title>
    <description>tshark input wrapper for converting pcap to XML using tshark and indexing the output</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>xml</streaming_mode>
    <use_single_instance>false</use_single_instance>

    <endpoint>
        <args>    
            <arg name="name">
                <title>Tshark Input Name</title>
                <description>Name of this tshark input definition</description>
            </arg>
            <arg name="tshark_command">
                <title>Tshark Command</title>
                <description> tshark command line, tshark if in the system PATH or full path to the tshark binary (/usr/local/bin/tshark). Environment variables in the format $VARIABLE$ can be included and they will be substituted.</description>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
            </arg>
            <arg name="tshark_filter">
                <title>Tshark Filter Argument</title>
                <description>tshark filter string</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg> 
            <arg name="tshark_output">
                <title>tshark output format (pdml or psml) - psml will have packet headers only, pdml has full packet payload decode</title>
                <description>tshark output format</description>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
            </arg> 

            <arg name="pcap_path">
                <title>Packet Capture Path</title>
                <description>Packet Capture Path on filesystem</description>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
            </arg>      
            <arg name="pcap_remove">
                <title>Packet Capture Removal After Processing</title>
                <description>Whether to remove pcap files when complete or not - checked will remove files</description>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
            </arg>
        </args>
    </endpoint>
</scheme>
"""

def do_validate():
    
    try:
        config = get_validation_config() 
        
        tshark_command=config.get("tshark_command")
        tshark_output=config.get("tshark_output")
        tshark_filter=config.get("tshark_filter")
        pcap_path=config.get("pcap_path")
        
        validationFailed = False
    
        if not tshark_command is None and which(tshark_command) is None:
            print_validation_error("Command name "+tshark_command+" does not exist")
            validationFailed = True
        if validationFailed:
            sys.exit(2)
               
    except RuntimeError,e:
        logging.error("Looks like an error: %s" % str(e))
        sys.exit(1)
        raise   

## helper for command validation from command

def which(program):

    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None

def do_run():
    config = get_input_config()
    tshark_command=config.get("tshark_command")
    tshark_output=config.get("tshark_output")
    tshark_filter=config.get("tshark_filter")
    pcap_path=config.get("pcap_path")

    tshark_command_string = tshark_command
    if tshark_filter:
        tshark_command_string = tshark_command + " -R " + tshark_filter
    
    try:    
        env_var_tokens = re.findall("\$(?:\w+)\$",tshark_command_string)
        for token in env_var_tokens:
            tshark_command_string = tshark_command_string.replace(token,os.environ.get(token[1:-1]))
    except: 
        e = sys.exc_info()[1]
        logging.error("Looks like an error replacing environment variables: %s" % str(e))  


  
