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


 #read XML configuration passed from splunkd, need to refactor to support single instance mode
def get_input_config():
    config = {}

    try:
        # read everything from stdin
        config_str = sys.stdin.read()

        # parse the config XML
        doc = xml.dom.minidom.parseString(config_str)
        root = doc.documentElement
        conf_node = root.getElementsByTagName("configuration")[0]
        if conf_node:
            logging.debug("XML: found configuration")
            stanza = conf_node.getElementsByTagName("stanza")[0]
            if stanza:
                stanza_name = stanza.getAttribute("name")
                if stanza_name:
                    logging.debug("XML: found stanza " + stanza_name)
                    config["name"] = stanza_name

                    params = stanza.getElementsByTagName("param")
                    for param in params:
                        param_name = param.getAttribute("name")
                        logging.debug("XML: found param '%s'" % param_name)
                        if param_name and param.firstChild and \
                           param.firstChild.nodeType == param.firstChild.TEXT_NODE:
                            data = param.firstChild.data
                            config[param_name] = data
                            logging.debug("XML: '%s' -> '%s'" % (param_name, data))

        checkpnt_node = root.getElementsByTagName("checkpoint_dir")[0]
        if checkpnt_node and checkpnt_node.firstChild and \
           checkpnt_node.firstChild.nodeType == checkpnt_node.firstChild.TEXT_NODE:
            config["checkpoint_dir"] = checkpnt_node.firstChild.data

        if not config:
            raise Exception, "Invalid configuration received from Splunk."

        
    except Exception, e:
        raise Exception, "Error getting Splunk configuration via STDIN: %s" % str(e)

    return config

#read XML configuration passed from splunkd, need to refactor to support single instance mode
def get_validation_config():
    val_data = {}

    # read everything from stdin
    val_str = sys.stdin.read()

    # parse the validation XML
    doc = xml.dom.minidom.parseString(val_str)
    root = doc.documentElement

    logging.debug("XML: found items")
    item_node = root.getElementsByTagName("item")[0]
    if item_node:
        logging.debug("XML: found item")

        name = item_node.getAttribute("name")
        val_data["stanza"] = name

        params_node = item_node.getElementsByTagName("param")
        for param in params_node:
            name = param.getAttribute("name")
            logging.debug("Found param %s" % name)
            if name and param.firstChild and \
               param.firstChild.nodeType == param.firstChild.TEXT_NODE:
                val_data[name] = param.firstChild.data

    return val_data

if __name__ == '__main__':
      
    if len(sys.argv) > 1:
        if sys.argv[1] == "--scheme":           
            do_scheme()
        elif sys.argv[1] == "--validate-arguments":
            do_validate()
        else:
            usage()
    else:
        do_run()
        
    sys.exit(0) 
