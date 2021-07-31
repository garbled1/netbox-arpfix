# netbox-arpfix
Search netbox for mac addresses and patch in missing entries

# usage
Run arp-scan with the -x option on a subnet, or your entire network, and dump
the output to a file.  Then process the file with this tool.

    usage: arp.py [-h] [-v] -f FILENAME [-d DNS_OVERRIDE] [-n BASE_URI] [-t TOKEN]
                  [-w]
    
    Search for mac addresses in netbox, and optionally add them to devices that
    are missing. Uses output from arp-scan -x.
    
    optional arguments:
      -h, --help            show this help message and exit
      -v, --verbose         Be verbose
      -f FILENAME, --file FILENAME
                            File to parse
      -d DNS_OVERRIDE, --dns_override DNS_OVERRIDE
                            Override DNS with resolver IP
      -n BASE_URI, --netbox_url BASE_URI
                            Netbox API URL in the form http://host/api
      -t TOKEN, --token TOKEN
                            Netbox API Token
      -w, --write           Enable Write mode

# notes
By default the tool will read whatever file you give it, and look for the mac
addresses in netbox, warning you when it cannot find one.  If run with the -w
argument, and a token that allows write, it will add mac addresses to interfaces
that are missing one.  It will not overwrite an existing mac, if one exists and
does not match.

# Example output

    [garbled@polaris:~/test]$ ./arp.py -f out.txt -d 192.168.10.x -v
    Found xx:xx:xx:xx:xx:xx on Mebsuta
    Found 1e:xx:xx:xx:xx:xx on VM hadar
    Couldn't find xx:xx:xx:xx:xx:xx (baham) with ip 192.168.10.xx (TRENDnet, Inc.) in netbox

    [garbled@polaris:~/test]$ ./arp.py -f out.txt -d 192.168.10.x -t xxxxxxxxxx -w
    Found 192.168.10.x on interface ens18 of VM hadar
    Adding mac xx:xx:xx:xx:xx:xx to interface ens18 on VM hadar
    Found 192.168.10.xx on interface Ethernet of device atria
    Adding mac xx:xx:xx:xx:xx:xx to interface Ethernet on device atria

# acknowlegements

Brutally hacked up from arp.py in https://github.com/Gelob/netbox_import
