import nmap
import os

# Set the NMAP_PRIVILEGED_EXEC environment variable to 'always'
os.environ['NMAP_PRIVILEGED_EXEC'] = 'always'

scanner = nmap.PortScanner()

# Define target IP address or hostname
target = input("Enter the target IP address or hostname: ")

# Prompt the user for ports or port range (e.g., 80 or 80-100)
port_input = input("Enter the port or port range (e.g., 80 or 80-100): ")

# Additional Nmap arguments
nmap_args = "-p {0} -sV -A -T4 --min-rate 500 --script vuln".format(port_input)

# Run the Nmap scan with the specified arguments
scanner.scan(target, arguments=nmap_args)

# Print the scan results
for host in scanner.all_hosts():
    print("Host: ", host)
    for proto in scanner[host].all_protocols():
        print("Protocol: ", proto)
        ports = list(scanner[host][proto].keys())
        ports.sort(key=lambda x: int(x))
        for port in ports:
            port_info = scanner[host][proto][port]
            print("Port: ", port, "State: ", port_info['state'])
            print("Service: ", port_info['name'])
            print("Version: ", port_info['product'], port_info['version'])
            
            # Check if the 'osclass' key exists before trying to access it
            if 'osclass' in port_info:
                print("OS Type: ", port_info['osclass'][0]['osfamily'])
                print("OS Accuracy: ", port_info['osclass'][0]['accuracy'])
            else:
                print("OS information not available for this port.")
            
            # Check if the 'script' key exists before trying to access it
            if 'script' in port_info:
                # Check if the 'vuln' key exists within the 'script' dictionary
                if 'vuln' in port_info['script']:
                    print("Script Output: ", port_info['script']['vuln'])
                else:
                    print("Script information not available for this port.")
            else:
                print("Script information not available for this port.")
