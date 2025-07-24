#!/bin/bash

sudo airmon-ng check kill
rfkill unblock 1
sudo airmon-ng start wlp1s0

