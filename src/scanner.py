__author__ = "Daniel Torac"

import nmap
from getmac import get_mac_address


class Scanner:
    def __init__(self):
        ip = str(input("Enter your IP (ecample: 192.168.1.1/24): "))
        self.ip = ip

    def get_mac(self, ip):
        mac = get_mac_address(ip=ip)
        return mac

    def scan_ips(self):
        try:
            network = self.ip
            print()
            print("<<< Scanning network >>>")
            print("-------------------------")
            print()
            nm = nmap.PortScanner()
            nm.scan(hosts=network, arguments="-sn")
            hosts = [(x, nm[x]["status"]["state"]) for x in nm.all_hosts()]
            for host, status in hosts:
                if len(host) == 11:
                    print(f"{host}  \t{status}\t\t{self.get_mac(ip=host)}")
                if len(host) == 12:
                    print(f"{host} \t{status}\t\t{self.get_mac(ip=host)}")
                if len(host) == 13:
                    print(f"{host}\t{status}\t\t{self.get_mac(ip=host)}")
        except Exception as e:
            print(f"Check your IP: {e}")