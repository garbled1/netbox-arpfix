#!/usr/bin/python3
import requests
import csv
import dns
import argparse
from dns import resolver
from dns import reversename

from requests.packages.urllib3.exceptions import InsecurePlatformWarning
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.packages.urllib3.exceptions import SNIMissingWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
requests.packages.urllib3.disable_warnings(SNIMissingWarning)

# generate API token at https://netbox.mydomain.com/user/api-tokens
token = "123fa7807623fba514c09641b7b323896434a94"
baseURI = "http://fafnir.garbled.net/api"

parser = argparse.ArgumentParser(description="Search for mac addresses in netbox, and optionally add them to devices that are missing.  Uses output from arp-scan -x.")
parser.add_argument('-v', '--verbose',
                    action='store_true',
                    dest='verbose',
                    help='Be verbose')
parser.add_argument('-f', '--file',
                    dest='filename',
                    help='File to parse',
                    type=str,
                    required=True)
parser.add_argument('-d', '--dns_override',
                    dest='dns_override',
                    help='Override DNS with resolver IP',
                    type=str)
parser.add_argument('-n', '--netbox_url',
                    dest='base_uri',
                    default=baseURI,
                    help='Netbox API URL in the form http://host/api',
                    type=str)
parser.add_argument('-t', '--token',
                    dest='token',
                    default=token,
                    help='Netbox API Token',
                    type=str)
parser.add_argument('-w', '--write',
                    dest='write',
                    action='store_true',
                    default=False,
                    help='Enable Write mode')

args = parser.parse_args()

if args.dns_override is not None:
    dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
    dns.resolver.default_resolver.nameservers = [args.dns_override]

headers = {"Accept": "application/json", "Authorization": "Token " + args.token}


def find_interface_id_for_dev_id(id):
    ilookup = "%s/dcim/interfaces/?id=%s" % (args.base_uri, id)
    r = requests.get(ilookup, headers=headers, verify=False)
    jdata = r.json()
    if jdata["count"] != 1:
        return False
    instance = jdata["results"][0]
    return instance["id"]


def find_interface_id_for_vm_id(id):
    ilookup = "%s/virtualization/interfaces/?id=%s" % (args.base_uri, id)
    r = requests.get(ilookup, headers=headers, verify=False)
    jdata = r.json()
    if jdata["count"] != 1:
        return False
    instance = jdata["results"][0]
    return instance["id"]


def interface_lookup(interface, device):
    ilookup = "%s/dcim/interfaces/?name=%s&device=%s" % (args.base_uri, interface, device)
    r = requests.get(ilookup, headers=headers, verify=False)
    jdata = r.json()
    if jdata["count"] == 1:
        instance = jdata["results"][0]
        return instance["id"]
    elif jdata["count"] == 0:
        return False
    else:
        print("interface_lookup fail {}", jdata)
        raise Exception(
            "The mentioned interface does not exist on this device or returned more than 1 result"
        )


def ipaddress_lookup(ip):
    ilookup = "%s/ipam/ip-addresses/?q=%s/" % (args.base_uri, ip)
    r = requests.get(ilookup, headers=headers, verify=False)
    jdata = r.json()
    if jdata["count"] == 1:
        instance = jdata["results"][0]
        return instance["id"]
    elif jdata["count"] == 0:
        return False
    else:
        print("ip_lookup fail {}", jdata)
        raise Exception(
            "The mentioned ip address does not exist or returned more than 1 result"
        )

def ipaddress_assigned_obj_by_id(id):
    ilookup = "%s/ipam/ip-addresses/?id=%s" % (args.base_uri, id)
    r = requests.get(ilookup, headers=headers, verify=False)
    jdata = r.json()
    if jdata["count"] != 1:
        return False
    instance = jdata["results"][0]
    if instance["assigned_object"] is not None and "url" in instance["assigned_object"]:
        return instance["assigned_object"]["url"]
    return False


def vm_macaddress_lookup(mac):
    mlookup = "%s/virtualization/interfaces/?mac_address=%s" % (args.base_uri, mac)
    r = requests.get(mlookup, headers=headers, verify=False)
    jdata = r.json()
    if jdata["count"] == 1:
        instance = jdata["results"][0]
        return instance["virtual_machine"]["id"]
    elif jdata["count"] == 0:
        return False
    else:
        print("vm_mac_lu fail {}", jdata)
        raise Exception(
            "The mentioned mac address does not exist  or returned more than 1 result"
        )


def devices_macaddress_lookup(mac):
    mlookup = "%s/dcim/devices/?mac_address=%s" % (args.base_uri, mac)
    r = requests.get(mlookup, headers=headers, verify=False)
    jdata = r.json()
    # print(jdata)
    if jdata["count"] == 1:
        instance = jdata["results"][0]
        return instance["id"]
    elif jdata["count"] == 0:
        return False
    else:
        print("dmacl fail {}", jdata)
        raise Exception(
            "The mentioned mac address does not exist  or returned more than 1 result"
        )


def ipaddress_add(address, interface_id, vrf_id, status):
    ipadd = "%s/ipam/ip-addresses/" % (args.base_uri)
    data = {}
    data["address"] = address
    data["interface"] = interface_id
    data["vrf"] = vrf_id
    data["status"] = status
    r = requests.post(ipadd, headers=headers, verify=False, data=data)
    jdata = r.json()
    if r.status_code != 201:
        return False
        raise Exception("Failed to add ip address")
    else:
        return jdata["id"]


def device_lookup(device):
    dlookup = "%s/dcim/devices/?name=%s" % (args.base_uri, device)
    r = requests.get(dlookup, headers=headers, verify=False)
    jdata = r.json()
    if jdata["count"] == 1:
        instance = jdata["results"][0]
        return instance["id"]
    else:
        print("dl fail {}", jdata)
        raise Exception(
            "The mentioned device does not exist or returned more than 1 result"
        )


def device_lookup_by_id(id):
    dlookup = "%s/dcim/devices/?id=%s" % (args.base_uri, id)
    r = requests.get(dlookup, headers=headers, verify=False)
    jdata = r.json()
    if jdata["count"] == 1:
        instance = jdata["results"][0]
        return instance["name"]
    elif jdata["count"] == 0:
        return False
    else:
        print("dlbyid fail {}", jdata)
        raise Exception(
            "The mentioned mac address does not exist  or returned more than 1 result"
        )


def vm_lookup(id):
    vlookup = "%s/virtualization/virtual-machines/%s/" % (args.base_uri, id)
    r = requests.get(vlookup, headers=headers, verify=False)
    jdata = r.json()
    if jdata["name"]:
        return jdata["name"]
    else:
        raise Exception(
            "The mentioned device does not exist or returned more than 1 result"
        )


def add_mac_to_interface(url, macaddr):
    r = requests.get(url, headers=headers, verify=False)
    jdata = r.json()
    if "device" in jdata and \
       "name" in jdata["device"] and \
       "name" in jdata:
        if jdata["mac_address"] is None:
            string = "Adding mac {} to interface {} on device {}"
            print(string.format(macaddr, jdata["name"], jdata["device"]["name"]))
            r = requests.patch(url, headers=headers, verify=False,
                               data={'mac_address': macaddr})
            if r.status_code != 200:
                jdata = r.json()
                print("Error setting macaddr: {}".format(jdata))
        else:
            fail = "Device {} has existing macaddr {} on interface {}, " \
                "not overwriting."
            print(fail.format(jdata["device"]["name"], jdata["mac_address"],
                              jdata["name"]))
    elif "virtual_machine" in jdata and \
         "name" in jdata["virtual_machine"] and \
         "name" in jdata:
        if jdata["mac_address"] is None:
            string = "Adding mac {} to interface {} on VM {}"
            print(string.format(macaddr, jdata["name"],
                                jdata["virtual_machine"]["name"]))
            r = requests.patch(url, headers=headers, verify=False,
                               data={'mac_address': macaddr})
            if r.status_code != 200:
                jdata = r.json()
                print("Error setting macaddr: {}".format(jdata))
        else:
            fail = "VM {} has existing macaddr {} on interface {}, " \
                "not overwriting."
            print(fail.format(jdata["virtual_machine"]["name"],
                              jdata["mac_address"],
                              jdata["name"]))


with open(args.filename, 'r') as f:
    arpt = []
    reader = csv.reader(f)
    for row in reader:
        stuff = dict()
        stuff['ip'] = row[0].split('\t')[0]
        stuff['mac'] = row[0].split('\t')[1]
        stuff['vendor'] = row[0].split('\t')[2]
        try:
            addr = reversename.from_address(stuff['ip'])
            stuff['name'] = resolver.query(addr, "PTR")[0].to_text().strip('.')
        except:
            stuff['name'] = 'NODNS'
            pass
        arpt.append(stuff)

    # Loop through all of the ip addresses returned
    for key in arpt:
        # print("STUFF:", key["ip"], key["vendor"], key["mac"])
        try:
            # if ipaddress_lookup(key["ip"]):
            #    pass
            if vm_macaddress_lookup(key["mac"]):
                vm = vm_lookup(vm_macaddress_lookup(key["mac"]))
                fail = "Found {} on VM {}"
                if args.verbose:
                    print(
                        fail.format(
                            key["mac"],
                            vm,
                        )
                    )
            elif devices_macaddress_lookup(key["mac"]):
                device = device_lookup_by_id(devices_macaddress_lookup(key["mac"]))
                fail = "Found {} on {}"
                if args.verbose:
                    print(
                        fail.format(
                            key["mac"],
                            device,
                        )
                    )
            # try to find the IP on a device, and fix
            elif ipaddress_lookup(key["ip"]) and ipaddress_assigned_obj_by_id(ipaddress_lookup(key["ip"])):
                devurl = ipaddress_assigned_obj_by_id(ipaddress_lookup(key["ip"]))
                r = requests.get(devurl, headers=headers, verify=False)
                jdata = r.json()
                if "device" in jdata \
                   and "name" in jdata["device"] \
                   and "name" in jdata:
                    string = "Found {} on interface {} of device {}"
                    print(string.format(key["ip"], jdata["name"],
                                        jdata["device"]["name"]))
                elif "virtual_machine" in jdata and \
                     "name" in jdata["virtual_machine"] and \
                     "name" in jdata:
                    string = "Found {} on interface {} of VM {}"
                    print(string.format(key["ip"], jdata["name"],
                                        jdata["virtual_machine"]["name"]))
                else:
                    print("Found {} on url {}".format(key["ip"], devurl))
                if args.write:
                    add_mac_to_interface(devurl, key["mac"])
            else:
                mac_url = "http://macvendors.co/api/%s" % (key["mac"])
                r = requests.get(mac_url)
                # print(r)
                if r.status_code == 200:
                    jdata = r.json()
                    # print(jdata)
                fail = "Couldn't find {} ({}) with ip {} ({}) in netbox"
                if r.status_code == 200 and "company" in jdata["result"]:
                    print(
                        fail.format(
                            key["mac"],
                            key["name"],
                            key["ip"],
                            jdata["result"]["company"],
                        )
                    )
                else:
                    print(
                        fail.format(
                            key["mac"],
                            key["name"],
                            key["ip"],
                            key["vendor"],
                        )
                    )

        except KeyboardInterrupt:
            break
        except Exception as ee:
            fail = "{} returned more than 1 result in Netbox, ignoring ({})."
            print(fail.format(key["ip"], ee))
