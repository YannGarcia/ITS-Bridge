#!/bin/bash

export LD_LIBRARY_PATH=/home/etsi/lib:$LD_LIBRARY_PATH
DATE=`date '+%Y-%m-%d %H:%M:%S'`
echo "Starting its_bridge_server service at ${DATE}"

/home/etsi/bin/its_bridge_server -c /home/etsi/etc/its_bridge/server.conf > /var/log/its_bridge_server.log 2>&1




