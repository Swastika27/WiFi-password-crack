#!/bin/bash

sudo airmon-ng stop wlp1s0mon
sudo service NetworkManager restart

# Revert back
# sudo ip link set mon0 down
# echo "mon0 down"
# sudo iw dev mon0 del
# echo "mon0 deleted"
