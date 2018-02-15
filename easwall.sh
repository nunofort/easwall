#!/usr/bin/env bash
#
#
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2012 Nuno Fortes (nunofort@gmail.com)
#
##############################################################################


if [ $# -eq 0 ]; then
echo "Easwall 1.3    Easy Firewall Script for IPTables"
echo "               by Nuno Fortes (nunofort@gmail.com)"
echo
echo "usage: $0 [interface] | [ext_interface]"
echo "       $0 stop - STOP/UNLOAD Firewall"
echo
exit 0
fi



DEBUG=true
IFACE=$1
if [ "$2" = "" ]; then
OFACE=ppp0
else
OFACE=$2
fi

echo "IFACE: $IFACE"
echo "OFACE: $OFACE"
IFACE_PATH=.
IPT=/sbin/iptables
IPT_SCRIPT=easwall_start.sh
IPT_SCRIPT_STOP=easwall_stop.sh


#IN_RULES=`awk -F: '{ print "INPUT ", $0; }' $IFACE/in.rules`
#IN_RULES=`cat $IFACE/in.rules | grep '\n'`
#IN_RULES=`cat $IFACE/in.rules | sed '\n'`
IN_RULES="${IFACE_PATH}/${IFACE}/in.rules"
OUT_RULES="${IFACE_PATH}/${IFACE}/out.rules"
FWD_RULES="${IFACE_PATH}/${IFACE}/fwd.rules"

#echo $IN_RULES

#ifconfig eth0 | awk '/TX bytes:/ { TX=substr($6,7); print TX }'`

#rule=`echo ${RULE} | awk '{ print $1; }'`
#action=`echo ${RULE} | awk '{ print $2; }'`
#host=`echo ${RULE} | awk '{ print $3; }'`
#port=`echo ${RULE} | awk '{ print $4; }'`

if [ "$1" = "stop" ]; then
cat >> $IPT_SCRIPT_STOP <<EOF
echo "Shutdown Firewall..."
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -F
iptables -F -t nat
EOF
exit 0
fi


rule_add() {
local chain=$1
local action=$2
local host=$3
local sport=$4
local dport=$5
local proto=$6
local log=$7
local param=""
#echo "RULE [ $@ ]"

if [ "$proto" = "" ]; then
proto=all
fi

#if [ "${sport}" = "" ]; then
#port=0
#fi

if [ "${chain}" = "INPUT" ]; then
iop="-i"
hop="-s"
else
iop="-o"
hop="-d"
fi

const="-A ${chain} $iop ${IFACE}"
param=""

if [ "${host}" != "all" ]; then
param="${param} ${hop} ${host}" 
fi

if [ "${sport}" != "0" ]; then
param="${param} --sport ${sport}" 
fi

if [ "${dport}" != "0" ]; then
portsx=`echo ${dport} | grep ':'`
portsy=`echo ${dport} | grep ','`
if [ "$portsx" != "" ]; then
param="${param} -m multiport --dports ${portsx}"
elif [ "$portsy" != "" ]; then
param="${param} -m multiport --dports ${portsy}"
else
param="${param} --dport ${dport}" 
fi
fi

if [ "${action}" = "deny" ]; then 
action=REJECT
#action=DROP
if [ "$log" = "log" ]; then log=LOGDROP; fi;
else
action=ACCEPT
if [ "$log" = "log" ]; then log=LOGACCEPT; fi;
fi


#echo "RULE [${chain}] [${action}] [${host}] [${sport}] [${dport}]"

if [ "${log}" = "" ]; then 
param="${param} -j ${action}"
else
param="${param} -j ${log}" 
fi


if [ "${proto}" = "all" ]; then 
out="$IPT $const -p tcp $param"
out="$out\n$IPT $const -p udp $param"
#elif [ "${proto}" = "icmp" ]; then
#out="$IPT $const -p $proto $param"
else
out="$IPT $const -p $proto $param"
fi

if [ "${action}" = "deny" ] && [ "${host}" = "all" ]; then
echo $log
if [ "${log}" = "log" ]; then 
out="$IPT -P $chain LOGDROP"
else
out="$IPT -P $chain DROP"
fi
fi

if [ "${DEBUG}" = "true" ]; then
echo "${out}"
fi

#echo "${out}"
echo "$out" >> $IPT_SCRIPT

#$IPT -A LOGDROP $iop ${IFACE} -j LOG --log-level info --log-prefix "${chain} ${action} -- " --log-ip-options --log-tcp-options

#$IPT -A ${chain} $iop ${IFACE} $param -j LOGDROP

}

fwd_add() {
local action=$1
local shost=$2
local sport=$3
local dhost=$4
local dport=$5
local proto=$6
local log=$7
local param=""
echo "RULE [ $@ ]"


if [ "$proto" = "" ]; then
proto=tcp
#NOTE: MUST BE TCP TO RESTRICT BY PORT!
fi

if [ "${action}" = "allow" ]; then
rule="FORWARD"
param="-A $rule -p $proto -s $shost --dport $dport -j ACCEPT"
#param="-A $rule -p $proto -s $shost --sport $sport -d $dhost --dport $dport -j ACCEPT"
#param="-i $IFACE -o $OFACE -j ${action}"
elif [ "${action}" = "deny" ]; then 
action="REJECT"
#LOGGING REJECT
if [ "$log" = "log" ]; then action=LOGDROP; fi;

if [ "${shost}" = "all" ]; then
param="-A $rule -j $action"
else
param="-A $rule -s $shost -j $action"
fi
fi

if [ "${action}" = "nat" ]; then
param="-t nat -A POSTROUTING -o $OFACE -j MASQUERADE"
#param="-t nat -A POSTROUTING -s $shost -o $OFACE -j MASQUERADE"
fi
if [ "${action}" = "dnat" ]; then
action=DNAT
param="-A PREROUTING -t nat -p $proto -d $shost --dport $sport -m state --state NEW,ESTABLISHED,RELATED -j ${action} --to-destination $4:$5"
fi
if [ "${action}" = "snat" ]; then
action=SNAT
# NAT inside LAN!
param="-A POSTROUTING -t nat -p $proto -s $shost --sport $sport -m state --state NEW,ESTABLISHED,RELATED -j ${action} --to-source $4"
fi
if [ "${action}" = "redir" ]; then
action=REDIRECT
param="-A PREROUTING -t nat -p $proto -s $shost --dport $sport -j $action --to-port $dport -d $dhost"
#param="-A PREROUTING -t nat -i $OFACE -p $proto --dport $sport -j $action –-to-port $dport -d $dhost"
fi

if ["${action}" = "deny"] && ["${host}" = "all"]; then
if [ "$log" = "log" ]; then
param="-P ${chain} LOGDROP"
else
param="-P ${chain} DROP"
fi
fi

#echo "$IPT $param"
echo "$IPT $param" >> $IPT_SCRIPT

if [ "${DEBUG}" = "true" ]; then
echo "$IPT ${param}"
fi
}


rm -f $IPT_SCRIPT

cat >> $IPT_SCRIPT <<EOF
#!/bin/sh
#
#echo "[+] Loading modules..."
#
#/sbin/depmod -a
#/sbin/modprobe ip_tables
#/sbin/modprobe ip_conntrack
#/sbin/modprobe ip_conntrack_ftp
#/sbin/modprobe ip_conntrack_irc
#/sbin/modprobe iptable_nat
#/sbin/modprobe ip_nat_ftp
#echo "1" > /proc/sys/net/ipv4/ip_forward
#echo "1" > /proc/sys/net/ipv4/ip_dynaddr

echo "......................................................"
echo "[+] START FIREWALL on interface...$1"
echo "......................................................"


echo "[+] Setting MAIN POLICY..."
$IPT -P INPUT ACCEPT
$IPT -P OUTPUT ACCEPT
$IPT -P FORWARD ACCEPT
echo "[+] Flushing FIREWALL Rules..."
$IPT -F
$IPT -F -t nat
$IPT -X LOGDROP
$IPT -X LOGACCEPT
#$IPT -F INPUT
#$IPT -F OUTPUT
#$IPT -F FORWARD

echo "[+] CREATING LOG CHAIN..."
#$IPT -N LOG_INPUT
#$IPT -N LOG_OUTPUT
$IPT -N LOGDROP
$IPT -N LOGACCEPT

#debug,info
$IPT -A LOGDROP -j LOG --log-level debug --log-prefix "IPTABLES DROP -- " --log-ip-options --log-tcp-options
$IPT -A LOGDROP -j DROP
$IPT -A LOGACCEPT -j LOG --log-level debug --log-prefix "IPTABLES ACCEPT -- " --log-ip-options --log-tcp-options
$IPT -A LOGACCEPT -j ACCEPT

echo "[+] Setting Loopback Device Rules..."
#MUST FOR INTERNAL OUTBOUND
#iptables -A INPUT -i lo -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT
$IPT -A FORWARD -o lo -j ACCEPT
$IPT -A FORWARD -i lo -j ACCEPT

#echo "[+] Defending from Special Attacks, uncomment..."
# Protege contra os "Ping of Death"
#$IPT -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
# Protege contra os ataques do tipo "Syn-flood, DoS, etc"
#$IPT -A FORWARD -p tcp -m limit --limit 1/s -j ACCEPT
# Permitir repassamento (NAT,DNAT,SNAT) de pacotes etabilizados e os relatados ...
#$IPT -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
# Logar os pacotes mortos por inatividade ...
#$IPT -A FORWARD -m limit --limit 3/minute --limit-burst 3 -j LOG
# Protege contra port scanners avançados (Ex.: nmap)
#$IPT -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
# Protege contra pacotes que podem procurar e obter informações da rede interna ...
#$IPT -A FORWARD --protocol tcp --tcp-flags ALL SYN,ACK -j DROP
# Protege contra todos os pacotes danificados e ou suspeitos ...
#$IPT -A FORWARD -m unclean -j DROP
# Bloqueando tracertroute
#$IPT -A INPUT -p udp -s 0/0 -i $IFACE --dport 33435:33525 -j DROP
# Protecoes contra ataques
#$IPT -A INPUT -m state --state INVALID -j DROP

EOF

cat >> $IPT_SCRIPT <<EOF
echo "....................................................."
echo "[+] Setting INPUT RULES...${IN_RULES}"
echo "....................................................."
$IPT -A INPUT -i $IFACE -p icmp -j ACCEPT
$IPT -A INPUT -i $IFACE -p udp -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT -i $IFACE -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
EOF

if [ ! -f $IN_RULES ]; then
exit 0
fi

while read RULE 
do

if [ "${RULE}" != "" ]; then
#echo "RULE ${RULE}"
x=`echo ${RULE} | awk '{x=substr($1,1,1); print x }'`
if [ "$x" != "#" ]; then
#echo "INPUT ${RULE}"
rule_add INPUT ${RULE}
fi
fi

done < $IN_RULES 

if [ ! -f $OUT_RULES ]; then
exit 0
fi

cat >> $IPT_SCRIPT <<EOF
echo "..................................................."
echo "[+] Setting OUTPUT RULES...${OUT_RULES}"
echo "..................................................."
$IPT -A OUTPUT -o $IFACE -p icmp -j ACCEPT
EOF

while read RULE 
do

if [ "${RULE}" != "" ]; then
#echo "RULE ${RULE}"
x=`echo ${RULE} | awk '{x=substr($1,1,1); print x }'`
if [ "$x" != "#" ]; then
#echo "OUTPUT ${RULE}"
#else
rule_add OUTPUT ${RULE}
fi
fi

done < $OUT_RULES 

cat >> $IPT_SCRIPT <<EOF
echo "..................................................."
echo "[+] Setting FORWARD RULES...${FWD_RULES}"
echo "..................................................."
#$IPT -t nat -F
$IPT -A FORWARD -i $OFACE -o $IFACE -m state --state ESTABLISHED,RELATED -j ACCEPT
#$IPT -A FORWARD -i $IFACE -o $OFACE -j ACCEPT
#$IPT -t nat -A POSTROUTING -o $OFACE -j MASQUERADE
$IPT -A FORWARD -i $OFACE -o $IFACE -p icmp -j ACCEPT
EOF

if [ ! -f $FWD_RULES ]; then
exit 0
fi

while read RULE 
do
if [ "${RULE}" != "" ]; then
#echo "RULE ${RULE}"
x=`echo ${RULE} | awk '{x=substr($1,1,1); print x }'`
if [ "$x" != "#" ]; then
#echo "FORWARD ${RULE}"
#else
fwd_add ${RULE}
fi
fi
done < $FWD_RULES 



#watch logging
#tail -f /var/log/messages

