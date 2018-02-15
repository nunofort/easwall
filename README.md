
Easwall is an easy Firewall script for IPTables.

CONFIG
------

Setup any script parameters if needed.
IFACE_PATH or other variables.


RULE FILES - examples
----------------------

[eth0/in.rules]
allow all 0 80 tcp
allow all 0 443 tcp
#allow all 22 0 tcp
#allow all 0 0 icmp log
deny all 0 0 all log

[eth0/out.rules]
#RULE HOST SRC_PORT DST_PORT PROTO ?LOG
allow all 0 53
allow all 0 5353
allow all 0 43
allow all 0 80
allow all 0 8080
allow all 0 443
allow all 0 22
allow all 0 20,21 tcp
allow all 0 23 tcp
allow all 0 25 tcp
allow all 0 1024:5000 all
allow all 0 0 icmp
#deny all 0 0
deny all 0 0 all log

[eth0/fwd.rules]
nat
allow 192.168.1.32 0 0 80 tcp
dnat 192.168.1.32 80 192.168.1.8 80 tcp
snat 192.168.1.8 80 192.168.1.32 0 tcp
#redir 192.168.1.32 80 192.168.1.8 80 tcp
deny all 0 all 0 tcp log
deny all 0 all 0 tcp

USAGE - examples
----------------

Easwall 1.3    Easy Firewall Script for IPTables
               by Nuno Fortes (nunofort@gmail.com)

usage: ./easwall.sh [interface] | [ext_interface]
       ./easwall.sh stop - STOP/UNLOAD Firewall


./easwall.sh eth0 ppp0
./easwall.sh stop

