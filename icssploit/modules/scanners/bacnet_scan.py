from icssploit import (
    exploits,       # exploit lib
    print_success,  # used to print success message
    print_status,   # used to print normal message
    print_error,    # used to print error message
    mute,           # used to mute function print to stdout
    validators,     # used to verify module options value
)

from icssploit.utils import *

# Define the scan class
class Exploit(exploits.Exploit):
    # Define info about the exploit
    __info__ = {
        'name': 'bacnet device scan',
        'authors': [
            'lorenzo bruno <lorenzo.bruno7[at]studenti.unimi.it>' 
        ],
        'description': 'Scan all bacnet device.',
        'references': [
        ],
    }

    # Parameters used by the scan  
    target = exploits.Option('')
    port = exploits.Option('47808', 'bacnet port, default is 47808/UDP (0xBAC0)', validators=validators.integer)
    exploit_attributes = exploits.Option()

    # Function to run the scan using nmap
    def run(self):
        print_status("Scanning the target: " + self.target + " with port: " + str(self.port))
        nm = nmap.PortScanner()
        scan_result = nm.scan(self.target, str(self.port), arguments='--script bacnet-info -sU', sudo=True)
        if self.target in scan_result['scan']:
            host_info = scan_result['scan'][self.target]
            print(f"Host is up ({host_info['status']['state']} state).\n")
            if 'udp' in host_info and int(self.port) in host_info['udp']:
                port_info = host_info['udp'][int(self.port)]
            script_output = port_info.get('script', {}).get('bacnet-info', 'No additional info')
            print(script_output)
            print(f"Nmap done: scanned in {scan_result['nmap']['scanstats']['elapsed']} seconds")
        else:
            print(f"No information available for IP: {self.target}")