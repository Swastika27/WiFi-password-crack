#!/bin/bash

sudo airmon-ng check kill
rfkill unblock 1
sudo airmon-ng start wlp1s0

# # List interfaces
# echo "available interfaces"
# iw dev

# Enable monitor mode
# 2. Create a monitor interface without external tools
# sudo iw dev wlp1s0 interface add mon0 type monitor
# echo "created monitor mode interface mon0"
# sudo systemctl stop NetworkManager
# sudo systemctl stop wpa_supplicant
# # 3. Bring it up
# sudo ip link set mon0 up
# echo "interface mon0 up"
# sudo iw dev wlp1s0 set channel 6

