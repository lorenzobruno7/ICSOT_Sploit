from icssploit import (
    exploits,       # exploit lib
    print_success,  # used to print success message
    print_status,   # used to print normal message
    print_error,    # used to print error message
    mute,           # used to mute function print to stdout
    validators,     # used to verify module options value
)

from icssploit.utils import *

TABLE_HEADER = ["Vendor ID", "Vendor Name", "Object-identifier ", "Firmware", "Application Software", "Object Name", "Model Name", "IP Address"]

# Define the scan class
class Exploit(exploits.Exploit):
    # Info about the exploit
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
    target = exploits.Option('', "String for hosts as nmap use it 'scanme.nmap.org'"
                                 " or '198.116.0-255.1-127' or '216.163.128.20/20'")
    # Define the port to scan
    port = exploits.Option(47808, 'Bacnet port, default is 47808/UDP (0xBAC0)', validators=validators.integer)
    verbose = exploits.Option(0, 'Scapy verbose level, 0 to 2', validators=validators.integer)
    output_file = exploits.Option('', "output file path")
    prova = exploits.Option('', "test per comando show options")
    result = []


    # Function to run the scan
    def run(self):
        if self.target == '':
            print_error("Please set a target to scan")
        else:
            print_status("Scanning the target: " + self.target + " with port: " + str(self.port))
            nm = nmap.PortScanner()
            # Nmap scan with specificed script for bacnet
            scan_result = nm.scan(self.target, str(self.port), arguments='--script bacnet-info -sU', sudo=True)
            # Check if the target is in the scan result 
            if self.target in scan_result['scan']:
                host_info = scan_result['scan'][self.target]
                print(host_info)
                print_success(f"Host is up ({host_info['status']['state']} state).")            
                if 'udp' in host_info and int(self.port) in host_info['udp']:
                    port_info = host_info['udp'][int(self.port)]
                script_output = port_info.get('script', {}).get('bacnet-info', 'No additional info')
                print_success(f"Nmap done: scanned in {scan_result['nmap']['scanstats']['elapsed']} seconds")
                print(script_output)
                self.result = script_output
            else:
                print_error(f"No information available for IP: {self.target}")

    def command_testprint(self, file_path, *args, **kwargs):
        print("test")
        print_error('ERROR')
        print_success('SUCCESS')
        

    def command_export(self, file_path, *args, **kwargs):
        if not self.result:
            print_error("No result to export. Please run the scan first.")
            return
        # Parse the script_output
        parsed_data = self.parse_script_output(self.result)
        # Add the IP address to each row
        for row in parsed_data:
            row.append(self.target)
        # Export to file
        export_table(file_path, TABLE_HEADER, parsed_data)
        print_success(f"Exported data to {file_path}")

    def parse_script_output(self, script_output):
        """
        Parses the script_output into a list of lists for export.
        """
        parsed_data = []
        data = {}
        for line in script_output.splitlines():
            if ": " in line:
                key, value = line.split(": ", 1)
                data[key.strip()] = value.strip()
        
        # Convert the dictionary into a list in the order of TABLE_HEADER
        row = [
            data.get("Vendor ID", ""),
            data.get("Vendor Name", ""),
            data.get("Object-identifier", ""),
            data.get("Firmware", ""),
            data.get("Application Software", ""),
            data.get("Object Name", ""),
            data.get("Model Name", "")
        ]
        parsed_data.append(row)
        return parsed_data