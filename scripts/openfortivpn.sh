#!/bin/bash
### BEGIN INIT INFO
# Provides:          openfortivpm
# Required-Start:    $all
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:
# Short-Description: Halts openfortivpn...
### END INIT INFO

export LD_LIBRARY_PATH=/home/etsi/lib:$LD_LIBRARY_PATH
DATE=`date '+%Y-%m-%d %H:%M:%S'`
echo "Starting openfortivpn service at ${DATE}" >> /var/log/openfortivpn.log 2>&1

case "$1" in
    start)
        /home/etsi/bin/openfortivpn -c /home/etsi/frameworks/etc/its_bridge/client.conf >> /var/log/openfortivpn.log 2>&1
        ;;
    stop)
        kill $(cat /var/run/openfortivpn.pid) >> /var/log/openfortivpn.log 2>&1
        ;;
    *)
        echo 'Usage: $0 {start|stop}'
        exit 1
        ;;
esac

exit 0
