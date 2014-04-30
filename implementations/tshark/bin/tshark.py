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



