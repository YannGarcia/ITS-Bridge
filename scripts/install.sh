#!/bin/sh

set -e
set -vx

if [ $# != 2 ]
then
    echo "Usage: sudo install.sh <VENDOR VPN Login> <VENDOR VPN password>"
    echo "E.g. sudo HOME_BIN=$HOME_BIN HOME_LIB=$HOME_LIB HOME_INC=$HOME_INC ./install.sh yann.garcia@fscom.fr 123456"
   exit -1
fi

# System update (for Debian)
apt-get update
apt-get dist-upgrade -y
apt-get install autoconf autopoint build-essential cmake g++ gcc gdb gettext git-core gnutls-bin libgnutls28-dev libssl-dev libtool iputils-ping ppp pkg-config sudo texinfo -y
apt-get autoremove --purge -y
apt-get autoclean

# Install additional tools & libraries
# libmicrohttpd
cd /home/etsi/frameworks
git clone https://git.gnunet.org/libmicrohttpd.git libmicrohttpd
cd libmicrohttpd/
autoreconf -fi
./configure --enable-https
make
make install PREFIX=/home/etsi

# Install ETSI ITS Bridge
cd /home/etsi/frameworks
git clone https://github.com/YannGarcia/ITS-Bridge.git its_bridge
cd ./its_bridge/objs
cmake .
make
make install PREFIX=/home/etsi

# openfortivpn
cd /home/etsi/frameworks
git clone https://github.com/adrienverge/openfortivpn.git
cd openfortivpn
./autogen.sh
./configure --prefix=/home/etsi --sysconfdir=/home/etsi/etc
make && make install
cat > /home/etsi/frameworks/its_bridge/etc/openfortivpn.cfg <<EOF
host = 212.234.160.11
port = 443
username = $1
password = $2
set-routes = 1
set-dns = 1
pppd-use-peerdns = 0
# X509 certificate sha256 sum, trust only this one!
trusted-cert = 394869a62b1efdec0f8546e0d8c7ecab278529b38bcc97db4f20fd873dd0672f
EOF

# Set correct uid & giud
cd /home/etsi
chown -R etsi:etsi ./frameworks/its_bridge ./frameworks/openfortivpn ./frameworks/libmicrohttpd $HOME_BIN $HOME_LIB $HOME_INC

# Create system links
mkdir -p /etc/its_bridge
ln -sf /home/etsi/frameworks/its_bridge/etc/client.conf /etc/its_bridge/client.conf
ln -sf /home/etsi/frameworks/its_bridge/etc/server.conf /etc/its_bridge/server.conf
ln -sf /home/etsi/frameworks/its_bridge/etc/webserver.conf /etc/its_bridge/webserver.conf
ln -sf /home/etsi/frameworks/its_bridge/etc/openfortivpn.conf /etc/its_bridge/openfortivpn.conf

ln -sf /home/etsi/frameworks/its_bridge/scripts/its_bridge_webserver.sh /etc/init.d/its_bridge_webserver
ln -sf /home/etsi/frameworks/its_bridge/scripts/its_bridge_client.sh /etc/init.d/its_bridge_client
ln -sf /home/etsi/frameworks/its_bridge/scripts/its_bridge_server.sh /etc/init.d/its_bridge_server
ln -sf /home/etsi/frameworks/its_bridge/scripts/openfortivpn.sh /etc/init.d/openfortivpn

# Setup Runlevels
update-rc.d openfortivpn defaults
update-rc.d its_bridge_webserver defaults
update-rc.d its_bridge_client defaults
update-rc.d its_bridge_server defaults

# Setup Runlevels
#cd /home/etsi/frameworks/its_bridge/scripts/
#cp *.service /etc/systemd/system

#sudo systemctl enable its_bridge_client
#sudo systemctl enable its_bridge_server
#sudo systemctl enable its_bridge_webserver
#sudo systemctl enable openfortivpn

#sudo systemctl status its_bridge_client
#sudo systemctl status its_bridge_server
#sudo systemctl status its_bridge_webserver
#sudo systemctl status openfortivpn

# End of installation
cd /home/etsi
echo "Installation done, please reboot the hardware."
echo "After reboot, connect to https://<$VENDOR VPN IP Address>:8888"

exit 0
