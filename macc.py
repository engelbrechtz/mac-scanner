from scapy.all import ARP, Ether, srp
import argparse

def scan(ip):
    # Create an ARP request packet
    arp_request = ARP(pdst=ip)

    # Create an Ethernet frame
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine the Ethernet frame and ARP request packet
    packet = ether/arp_request

    # Send the packet and receive the response
    result = srp(packet, timeout=3, verbose=0)[0]

    # Extract and print the MAC addresses and IP addresses of the devices
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

def main():
    parser = argparse.ArgumentParser(description="Scan for devices on the local network.")
    parser.add_argument("ip_range", help="IP range to scan (e.g., 192.168.1.0/24)")
    args = parser.parse_args()

    ip_range = args.ip_range
    devices = scan(ip_range)

    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

if __name__ == "__main__":
    main()
