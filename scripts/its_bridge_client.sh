#!/bin/bash

export LD_LIBRARY_PATH=/home/etsi/lib:$LD_LIBRARY_PATH
DATE=`date '+%Y-%m-%d %H:%M:%S'`
echo "Starting its_bridge_client service at ${DATE}"

/home/etsi/bin/its_bridge_client -c /home/etsi/etc/its_bridge/client.conf > /var/log/its_bridge_client.log 2>&1




