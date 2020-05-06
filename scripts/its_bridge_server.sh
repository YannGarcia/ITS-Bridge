#!/bin/bash

export LD_LIBRARY_PATH=/home/etsi/lib:$LD_LIBRARY_PATH
DATE=`date '+%Y-%m-%d %H:%M:%S'`
echo "Starting its_bridge_server service at ${DATE}" >> /var/log/its_bridge_server.log 2>&1

case "$1" in
    start)
        /home/etsi/bin/its_bridge_server -c /home/etsi/etc/its_bridge/server.conf >> /var/log/its_bridge_server.log 2>&1
        ;;
    stop)
        kill $(cat /var/run/its_bridge_server.pid) >> /var/log/its_bridge_server.log 2>&1
        ;;
    *)
        # On indique ici comment utiliser le script, c'est dans le cas où le script est appelé sans argument ou avec un argument invalide
        echo 'Usage: $0 {start|stop}'
        exit 1
        ;;
esac

exit 0





