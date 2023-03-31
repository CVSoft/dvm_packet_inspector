# DVM Packet Inspector
Connect to a [DVMHost FNE](https://github.com/dvmproject/dvmfne) or [simpleFNE](https://github.com/github.com/CVSoft/simpleFNE) instance and view detailed information about network P25 data units, useful as a debugging tool.

## Requirements
This runs in Python 3.4 or later. It runs using only standard libraries and does not have any dependencies. While only tested on Windows, it should not do anything platform-dependent. 

The file `dvm_packet_inspector_extras.py` referenced within DVM Packet Inspector contains more detailed name lookup tables for various data fields. This file is not necessary to run DVM Packet Inspector, and data values encountered during conventional P25 operation are included with DVM Packet Inspector. You can create your own version of this file by matching the format used in DVM Packet Inspector (you will end up with a Python file simply containing three dictionaries), but I do not know if I can distribute a complete version under a copyleft license. 

## Usage
Create a config file, in INI structure, containing your desired options. See the Configuring section for details. 

Then run DVM Packet Inspector on the command line with this config file's filename as the only positional argument, e.g. `python dvm_packet_inspector.py config.ini`. 

DVM Packet Inspector will attempt to log into the server, and once logged in, will wait for P25 traffic. When P25 traffic is received, a lot of information will get dumped to the console. This is primarily general information about what data unit was just received, plus a complete breakdown of the Link Control Word (transmitted during LDU1) and Encryption Sync Word (transmitted during LDU2). 

*I have not tested this on an actual DVM FNE; only on simpleFNE*. I make an effort to include the challenge handshake for login, and it should work in theory, but it has not been tested.

Exit DVM Packet Inspector with Ctrl-C. 

## Configuring
There are many configurable options in DVM Packet Inspector; all of these are in an INI-format file under a section titled Inspector. You can use the same config file you use for SimpleFNE, as the options live in different sections. The configurable options are:
* `ip`: the IPv4 address of the FNE to connect to. 
* `port`: the port number of the FNE to connect to. 
* `peer_id`: the DVMHost peer ID to use -- this is any integer from 0 to 4294967295. Note that DVM Packet Inspector enforces peer ID match in incomng packets. If you have problems with peer ID mismatch, set this to 0 and notify the developer of the FNE you are using. 
* `use_connect`: this tells the socket used to connect to the FNE to call connect() after creation. This is very much a debugging option and shouldn't make any difference whether it's set or unset. 
* `tickrate`: as the main thread runs asynchronously, this controls how frequently it checks for events, in Hz. This value should be left unconfigured in configuration files. 

The default configuration is given below:
```
[Inspector]
ip: 127.0.0.1
port: 54000
peer_id: 0
password: s3cr37w0rd
use_connect: true
tickrate: 20.0
```
