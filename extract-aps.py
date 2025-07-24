from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt

def extract_aps_from_capture(cap_file):
    packets = rdpcap(cap_file)
    ap_dict = {}

    for pkt in packets:
        if pkt.haslayer(Dot11Beacon) or (pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 5):  # Beacon or Probe Response
            bssid = pkt[Dot11].addr2
            essid = ""
            channel = None

            # Extract info from Dot11Elt layers
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0:  # SSID
                    essid = elt.info.decode(errors="ignore")
                elif elt.ID == 3:  # DS Parameter set (channel)
                    channel = int.from_bytes(elt.info, byteorder='little')
                elt = elt.payload.getlayer(Dot11Elt)

            if bssid not in ap_dict:
                ap_dict[bssid] = {
                    "ESSID": essid,
                    "Channel": channel,
                }

    return ap_dict

# Use on your .cap file
aps = extract_aps_from_capture("scan-aps-04.cap")

print("Access Points Found:")
for bssid, info in aps.items():
    print(f"BSSID: {bssid} | ESSID: {info['ESSID']} | Channel: {info['Channel']}")
