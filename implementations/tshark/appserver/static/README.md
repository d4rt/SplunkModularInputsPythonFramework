# Splunk tshark Modular Input v1
by Duncan Turnbull
April 2014
----

## Overview

This is a Splunk Modular Input for running TShark on directories of PCAP files
to convert them into PDML and stream the resulting data back into Splunk. It
requires tshark to be present, and is tested on MacOS and Linux.

## Dependencies
* Splunk 5.0 +
* Supported on MacOS and Linux
* tshark (from Wireshark)

## Setup
* Untar the release into your ``$SPLUNK_HOME/etc/apps`` directory
* Restart Splunk

## Environment variables
Environnment variables in the format ``$VARIABLE$`` can be included in the command name and path and they will be dynamically substituted ie: ``$SPLUNK_HOME$``

## Logging

Any modular input errors will get written to ``$SPLUNK_HOME/var/log/splunk/splunkd.log``


