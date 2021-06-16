#!/bin/bash
#########################################################################
#This script is to install various proxy and vpn tools and configure    #
#them for immediate use. Under Early Development. Written for Debian 10.#
#									#
#License is TBD at this time.						#
#Version 0.0.001							#
#########################################################################
## Set a cleanup function, in case we need to kill the background processes.
function clean_up {

    # Perform program exit housekeeping
    kill $dhparam_PID
    killall openssl
    exit
}

trap clean_up SIGHUP SIGINT SIGTERM
## Have OpenSSL start generating the Diffie-Hellman file in the background.
#openssl dhparam -out dh8192.pem 8192 >/dev/null 2>&1 &
#openssl dhparam -out dh4096.pem 4096 >/dev/null 2>&1 &
#openssl dhparam -out dh2048.pem 2048 >/dev/null 2>&1 &
#openssl dhparam -out dh1024.pem 1024 >/dev/null 2>&1 &
openssl dhparam -out dh512.pem 512 >/dev/null 2>&1 &
dhparam_PID=$1

## Create a random password.
OCSERVPASSWD=$(openssl rand -hex 16)

## Set a static password (Please only use for testing and otherwise leave commented out)
#OCSERVPASSWD=password
SHADOWSOCKSPASSWD=$(openssl rand -base64 16)
#SHADOWSOCKSPASSWD=password
SHADOWSOCKSPORT=$((1025 + $RANDOM % 65534))
#SHADOWSOCKSPORT=8389

echo "Cisco Anyconnect: $OCSERVPASSWD" > Passwords.txt
echo "Shadowsocks: $SHADOWSOCKSPASSWD" >> Passwords.txt
echo "Shadowsocks Port: $SHADOWSOCKSPORT" >> Passwords.txt

##We'll want to know what our default interface is now, before we modify anything. This'll store it in a variable for firewall rules later.
default_iface=$(awk '$2 == 00000000 { print $1 }' /proc/net/route)

##Set a few variables for later (Move this to a seprate vars file later and source it, which'll keep this file cleaner and easier to maintain)
#source ./vars
emailaddr=zach@gibbens.dev
fqdncertbot=vpn1.gibbens.dev
username=zachgibbens

## Update the system
sudo apt update
sudo apt -y full-upgrade

##Install Etckeeper, mainly so we have a record and a way to revert changes, just in case anything goes wrong.
sudo apt -y install etckeeper

## Install and configure unattended-upgrades
echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | sudo debconf-set-selections
sudo apt -y install unattended-upgrades
#sudo dpkg-reconfigure -fnoninteractive unattended-upgrades

## Install DNSMasq as our local DNS Server, we'll also use this for the various VPNs and proxies we install later.
sudo apt -y install dnsmasq
## Make backup of original config
FILE=/etc/dnsmasq.conf.orig
if [[ -f "$FILE" ]]
then
echo file exists, not copying.
else
sudo cp /etc/dnsmasq.conf /etc/dnsmasq.conf.orig
fi

## Make sure this server is using the DNS Server.
# This section is has yet to be built.
# It should be fine for the short term, since the VPN servers will still point to it and the proxies can use the system default servers
# From there we can remote in and manually make the changes. That said this is a high priority issue.

## We'll need a publicly trusted cert, so let's install certbot for letsencrypt.
sudo apt -y install certbot

## Run Certbot to get us a script.
#sudo certbot certonly -n --agree-tos --standalone --preferred-challenges http --email $emailaddr -d $fqdncertbot

##Install sniproxy to share TCP port 443
sudo apt -y install sniproxy

## Make a backup of the original config
FILE=/etc/sniproxy.conf.orig
if [[ -f "$FILE" ]]
then
echo file exists, not copying.
else
sudo cp /etc/sniproxy.conf /etc/sniproxy.conf.orig
fi

## Copy our sniproxy.conf file and restart sniproxy
sudo cp ./sniproxy.conf /etc/sniproxy.conf
sudo systemctl restart sniproxy.service

##Let's install and configure OpenConnect and change the port to avoid conflicts with nginx later.
sudo apt -y install ocserv

##I want to backup the default config file, but only if it's not already been done.
FILE=/etc/ocserv/ocserv.conf.orig
if [[ -f "$FILE" ]]
then
echo file exists, not copying.
else
sudo cp /etc/ocserv/ocserv.conf /etc/ocserv/ocserv.conf.orig
fi

##Let's strip out all the comments in the config (We'll still have them in the original file we just backed up, if we need them later.)
cat /etc/ocserv/ocserv.conf.orig | grep -v ^# | grep -v ^$ | \

##Now we'll change the tcp port ocserv listens on, as we're going to have nginx on port 443.
sed s/^tcp-port\ =\ 443/tcp-port\ =\ 8443/g | \

##Have ocserv only listen on localhost
sed '$a listen-host = 127.0.0.1' | \

## By default ocserv uses unix accounts above UID 1000, I'd rather it just get it's account info from a file.
sed s#'auth = "pam\[gid-min=1000\]"'#'auth = "plain\[passwd=/etc/ocserv/ocpasswd\]"'#g | \

## Enable MTU Discovery
sed s#'try-mtu-discovery = false'#'try-mtu-discovery = true'#g |\

## Change VPN Network address to something less conflicting.
sed s#'ipv4-network = 192.168.1.0'#'ipv4-network = 192.168.20.32'#g |\
sed s#'ipv4-netmask = 255.255.255.0'#'ipv4-netmask = 255.255.255.224'#g |\

## Modify the DNS Servers used.
grep -v ^dns\ = |\
grep -v ^route\ = |\
sed '$a dns = 9.9.9.9' | \
sed '$a dns = 149.112.112.112' |\

##Create new config file based on above changes
sudo tee /etc/ocserv/ocserv.conf

##Enable ip forwarding in the kernel
sudo sed -i s/\#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g /etc/sysctl.conf
sudo sed -i '$a net.core.default_qdisc=fq' /etc/sysctl.conf
sudo sed -i '$a net.ipv4.tcp_congestion_control=bbr' /etc/sysctl.conf
sudo sysctl -p

##Create user account file
echo $OCSERVPASSWD | sudo ocpasswd -c /etc/ocserv/ocpasswd $username

##Restart ocserv
sudo systemctl restart ocserv.service

##Install Nginx
sudo apt -y install nginx-full

## Backup Nginx's default sites file
FILE=/etc/nginx/sites-available/default.orig
if [[ -f "$FILE" ]]
then
echo file exists, not copying.
else
sudo cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.orig
fi

## Enable SSL on Nginx
cat /etc/nginx/sites-available/default.orig | sed s/'# listen 443 ssl default_server;'/'listen 4443 ssl default_server;'/g |\
sed s/'# listen \[::\]:443 ssl default_server;'/'listen \[::\]:4443 ssl default_server;'/g |\
sed s@'# include snippets/snakeoil.conf;'@'include snippets/snakeoil.conf;'@g |\
sudo tee /etc/nginx/sites-available/default

## Restart Nginx
sudo systemctl restart nginx.service

## Install Tinyproxy, Stunnel, Tor, Privoxy, Shadowsocks-libev and obfs4proxy
sudo apt -y install tinyproxy stunnel4 tor privoxy shadowsocks-libev obfs4proxy

##Backup config.json for shadowsocks-libev
FILE=/etc/shadowsocks-libev/config.json.orig
if [[ -f "$FILE" ]]
then
echo file exists, not copying.
else
sudo cp /etc/shadowsocks-libev/config.json /etc/shadowsocks-libev/config.json.orig
fi

## Copy our shadowsocks config and use random port and password.
sudo cat /etc/shadowsocks-libev/config.json.orig |\
sed '/\"password\":\"/c\ \ \ \ \"password\":\"'$SHADOWSOCKSPASSWD\"'' |\
sed '/\"server\":/c\ \ \ \ \"server\":\[\"::\",\ \"0.0.0.0\"\],' |\
sed s/'"server_port":8388,'/'"server_port":'$SHADOWSOCKSPORT,/g |\
sudo tee /etc/shadowsocks-libev/config.json

## Restart shadowsocks-libev
sudo systemctl restart shadowsocks-libev.service

## Setup IP MASQUERADING for VPN(s) with IPTABLES
sudo iptables -t nat -A POSTROUTING -o $default_iface -j MASQUERADE

## Setup rest of iptables firewall
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT ! -i $default_iface -j ACCEPT

## Setup iptables-persistent so our rules will survive reboots
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
sudo apt -y install iptables-persistent
sudo apt -y install v2ray
