import nmap
import os
import sys

os.environ['NMAP_PRIVILEGED_EXEC'] = 'always'

scanner = nmap.PortScanner()

target =  sys.argv[1]

port_input = sys.argv[2]

nmap_args = "-p {0} -sV -A -T4 --min-rate 500 --script vuln".format(port_input)
scanner.scan(target, arguments=nmap_args)

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
            
            if 'osclass' in port_info:
                print("OS Type: ", port_info['osclass'][0]['osfamily'])
                print("OS Accuracy: ", port_info['osclass'][0]['accuracy'])
            else:
                print("OS information not available for this port.")

            if 'script' in port_info:
                if 'vuln' in port_info['script']:
                    print("Script Output: ", port_info['script']['vuln'])
                else:
                    print("Script information not available for this port.")
            else:
                print("Script information not available for this port.")