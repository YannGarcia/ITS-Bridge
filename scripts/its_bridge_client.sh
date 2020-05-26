#!/bin/bash
### BEGIN INIT INFO
# Provides:          its_bridge_client
# Required-Start:    $all
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:
# Short-Description: Halts ITS-Bridge client...
### END INIT INFO

export LD_LIBRARY_PATH=/home/etsi/lib:$LD_LIBRARY_PATH
DATE=`date '+%Y-%m-%d %H:%M:%S'`
echo "Starting its_bridge_client service at ${DATE}" >> /var/log/its_bridge_client.log 2>&1

case "$1" in
    start)
        /home/etsi/bin/its_bridge_client -c /home/etsi/frameworks/etc/its_bridge/client.conf >> /var/log/its_bridge_client.log 2>&1
        ;;
    stop)
        kill $(cat /var/run/its_bridge_client.pid) >> /var/log/its_bridge_client.log 2>&1
        ;;
    *)
        echo 'Usage: $0 {start|stop}'
        exit 1
        ;;
esac

exit 0
