#!/bin/bash
### BEGIN INIT INFO
# Provides:          its_web_server_config
# Required-Start:    $all
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:
# Short-Description: Halts ITS-Bridge Web Server...
### END INIT INFO

export LD_LIBRARY_PATH=/home/etsi/lib:$LD_LIBRARY_PATH
DATE=`date '+%Y-%m-%d %H:%M:%S'`
echo "Starting its_web_server_config service at ${DATE}" >> /var/log/its_web_server_config.log 2>&1

case "$1" in
    start)
        /home/etsi/bin/its_web_server_config -c /home/etsi/frameworks/its_bridge/etc/webserver.conf >> /var/log/its_web_server_config.log 2>&1
        ;;
    stop)
        kill $(cat /var/run/its_web_server_config.pid) >> /var/log/its_web_server_config.log 2>&1
        ;;
    *)
        echo 'Usage: $0 {start|stop}'
        exit 1
        ;;
esac

exit 0
