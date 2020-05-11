#!/bin/sh

set -e
set -vx

if [ $# != 3 ]
then
    echo "Usage: sudo install.sh VENDOR_ID <VENDOR VPN Login> <VENDOR VPN password>"
    echo "E.g. ./install.sh fscom yann.garcia@fscom.fr 1234567"
   exit -1
fi

VENDOR=$1

# System update (for Debian)
apt-get update
apt-get dist-upgrade -y
apt-get install autoconf autopoint build-essential cmake g++ gcc gdb gettext git-core gnutls-bin libgnutls28-dev libssl-dev libtool iputils-ping ppp pkg-config sudo texinfo -y
apt-get autoremove --purge -y
apt-get autoclean

# Add $VENDOR user
useradd --create-home --shell /bin/bash $VENDOR
echo "$VENDOR:$VENDOR" | chpasswd
adduser $VENDOR sudo

cd /home/$VENDOR
mkdir -p bin lib include tmp frameworks etc

# Update profile
echo "" >> /etc/profile
echo 'export HOME=/home/$VENDOR' >> /etc/profile
echo 'export LD_LIBRARY_PATH=${HOME}/lib:$LD_LIBRARY_PATH' >> /etc/profile
echo 'export PATH=${HOME}/bin:$PATH' >> /etc/profile
echo 'export HOME_BIN=${HOME}/bin' >> /etc/profile
echo 'export HOME_LIB=${HOME}/lib' >> /etc/profile
echo 'export HOME_INC=${HOME}/include' >> /etc/profile
echo 'export HOME_ETC=${HOME}/etc' >> /etc/profile
echo 'cd ${HOME}' >> /etc/profile

cd /home/$VENDOR
echo "" >> ./.profile
echo 'export HOME=/home/$VENDOR' >> ./.profile
echo 'export LD_LIBRARY_PATH=${HOME}/lib:$LD_LIBRARY_PATH' >> ./.profile
echo 'export PATH=${HOME}/bin:$PATH' >> ./.profile
echo 'export HOME_BIN=${HOME}/bin' >> ./.profile
echo 'export HOME_LIB=${HOME}/lib' >> ./.profile
echo 'export HOME_INC=${HOME}/include' >> ./.profile
echo 'export HOME_ETC=${HOME}/etc' >> ./.profile
echo 'cd ${HOME}' >> ./.profile

# Install additional tools & libraries
# openfortivpn
cd /home/$VENDOR/frameworks
git clone https://github.com/adrienverge/openfortivpn.git
cd openfortivpn
./autogen.sh
./configure --prefix=/home/$VENDOR --sysconfdir=/home/$VENDOR/etc
make && make install
mkdir -p /home/$VENDOR/etc/openfortivpn
cat > /home/$VENDOR/etc/openfortivpn/${VENDOR}_plug_vpn.cfg <<EOF
host = 212.234.160.11
port = 443
username = $2
password = $3
set-routes = 1
set-dns = 1
pppd-use-peerdns = 0
# X509 certificate sha256 sum, trust only this one!
trusted-cert = 394869a62b1efdec0f8546e0d8c7ecab278529b38bcc97db4f20fd873dd0672f
EOF

# libmicrohttpd
cd /home/$VENDOR/frameworks
git clone https://git.gnunet.org/libmicrohttpd.git libmicrohttpd
cd libmicrohttpd/
autoreconf -fi
./configure --enable-https
make
make install PREFIX=/home/$VENDOR

# Install $VENDOR ITS Bridge
cd /home/$VENDOR/frameworks
git clone https://github.com/YannGarcia/ITS-Bridge.git its_bridge
cd ./its_bridge/objs
cmake .
make
make install PREFIX=/home/$VENDOR

# Set correct uid & giud
cd /home
chown -R $VENDOR:$VENDOR ./$VENDOR

# Change user
su - $VENDOR

# Setup Runlevels
cd /home/$VENDOR/frameworks/its_bridge/scripts/
ln -sf /home/$VENDOR/frameworks/its_bridge/scripts/openfortivpn.sh /etc/init.d/openfortivpn
ln -sf /home/$VENDOR/frameworks/its_bridge/scripts/its_bridge_webserver.sh /etc/init.d/its_bridge_webserver
ln -sf /home/$VENDOR/frameworks/its_bridge/scripts/its_bridge_client.sh /etc/init.d/its_bridge_client
ln -sf /home/$VENDOR/frameworks/its_bridge/scripts/its_bridge_server.sh /etc/init.d/its_bridge_server
update-rc.d openfortivpn defaults
update-rc.d its_bridge_webserver defaults
update-rc.d its_bridge_client defaults
update-rc.d its_bridge_server defaults

# Setup Runlevels
#cd /home/$VENDOR/frameworks/$VENDOR_bridge/scripts/
#cp *.service /etc/systemd/system

#sudo systemctl enable $VENDOR_bridge_client
#sudo systemctl enable $VENDOR_bridge_server
#sudo systemctl enable $VENDOR_bridge_webserver
#sudo systemctl enable openfortivpn

#sudo systemctl status $VENDOR_bridge_client
#sudo systemctl status $VENDOR_bridge_server
#sudo systemctl status $VENDOR_bridge_webserver
#sudo systemctl status openfortivpn

# End of installation
cd /home/$VENDOR/
echo "Installation done, please reboot the hardware."
echo "After reboot, connect to https://<$VENDOR VPN IP Address>:8888"

exit 0
