echo 65535 > /proc/sys/net/ipv4/netfilter/ip_conntrack_max

modprobe sch_fq_codel
modprobe ifb
ifconfig ifb0 up

mark()
{
 $2 -j MARK --set-mark $1
 $2 -j RETURN
}

OUTRATE=3300
#OUTRATESPLIT=666
OUTRATESPLIT=1000

#DOWNMAX=35000
DOWNMAX=33
DOWNRATE=31500


#MTU=1454
MTU=1500

iptables -t mangle -N TOINTERNET
iptables -t mangle -N FROMINTERNET
#iptables -t mangle -F
iptables -t mangle -A PREROUTING -i eth0 ! -d 192.168.0.0/16 -j TOINTERNET
iptables -t mangle -A PREROUTING -i eth1 ! -s 192.168.0.0/16 -j FROMINTERNET
#iptables -t mangle -A PREROUTING -i eth1 -j IMQ --todev 0

iptables -t mangle -A FORWARD -o eth1 -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1400:65495 -j TCPMSS --clamp-mss-to-pmtu

#CrashPlan, need tc to check tos = 0x04
mark "0x40" "iptables -t mangle -A TOINTERNET -s 192.168.1.250 -p tcp --dport 443"

#interactive
mark "0x20" "iptables -t mangle -A TOINTERNET -p udp --dport 9000:9010" #adam game

#time critical
#length match broken
##mark "0x10" "iptables -t mangle -A TOINTERNET -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK ACK -m length --length :64"
##mark "0x10" "iptables -t mangle -A TOINTERNET -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK ACK"

#from internet
mark "0x10" "iptables -t mangle -A FROMINTERNET -p udp --sport 9000:9010" #adam game
#mark "0x10" "iptables -t mangle -A FROMINTERNET -p icmp"
#mark "0x20" "iptables -t mangle -A FROMINTERNET"

#iptables -t mangle -L -v -n

#tc qdisc del dev imq0 root    2> /dev/null > /dev/null
tc qdisc del dev eth1 root    2> /dev/null > /dev/null
tc qdisc del dev eth1 ingress 2> /dev/null > /dev/null

tc qdisc del dev ifb0 root 2> /dev/null > /dev/null
tc qdisc del dev ifb0 ingress 2> /dev/null > /dev/null

#default traffic queue 30
tc qdisc add dev eth1 root handle 1: htb default 30
tc class add dev eth1 parent 1:0 classid 1:1 htb rate ${OUTRATE}kbit ceil ${OUTRATE}kbit burst 75k

tc class add dev eth1 parent 1:1 classid 1:10 htb rate ${OUTRATESPLIT}kbit ceil ${OUTRATE}kbit mtu ${MTU} prio 1
tc class add dev eth1 parent 1:1 classid 1:20 htb rate ${OUTRATESPLIT}kbit ceil ${OUTRATE}kbit mtu ${MTU} prio 2
tc class add dev eth1 parent 1:1 classid 1:30 htb rate ${OUTRATESPLIT}kbit ceil ${OUTRATE}kbit mtu ${MTU} prio 3
tc class add dev eth1 parent 1:1 classid 1:40 htb rate 58kbit ceil ${OUTRATE}kbit mtu ${MTU} prio 4

tc qdisc add dev eth1 parent 1:10 handle 10: sfq perturb 10 limit 43 #average packet size of 83 bytes
tc qdisc add dev eth1 parent 1:20 handle 20: sfq perturb 10 limit 5 #average packet size 52 bytes, 30ms buffer
tc qdisc add dev eth1 parent 1:30 handle 30: sfq perturb 10 limit 5 #average packet size 122 bytes, 35ms buffer
tc qdisc add dev eth1 parent 1:40 handle 40: sfq perturb 10 limit 70

#####first filter to match wins

#icmp
tc filter add dev eth1 parent 1:0 protocol ip prio 10 u32 match ip protocol 1 0xff flowid 1:10
#DNS
tc filter add dev eth1 parent 1:0 protocol ip prio 10 u32 match ip protocol 17 0xff match ip dport 53 0xffff flowid 1:10

tc filter add dev eth1 parent 1:0 protocol ip prio 10 u32 match ip protocol 6 0xff match u8 0x12 0xff at nexthdr+13 flowid 1:10 #SYN,ACK
tc filter add dev eth1 parent 1:0 protocol ip prio 10 u32 match ip protocol 6 0xff match u8 0x02 0xff at nexthdr+13 flowid 1:10 #SYN
tc filter add dev eth1 parent 1:0 protocol ip prio 10 u32 match ip protocol 6 0xff match u8 0x11 0xff at nexthdr+13 flowid 1:10 #FIN,ACK
tc filter add dev eth1 parent 1:0 protocol ip prio 10 u32 match ip protocol 6 0xff match u8 0x01 0xff at nexthdr+13 flowid 1:10 #FIN
tc filter add dev eth1 parent 1:0 protocol ip prio 10 u32 match ip protocol 6 0xff match u8 0x14 0xff at nexthdr+13 flowid 1:10 #RST,ACK

#tc matches into the IP packet from position 0 offset
#tc filter add dev eth1 parent 1:0 protocol ip prio 11 u32 match ip protocol 6 0xff match u8 0x10 0xff at nexthdr+13 match u16 0x0000 0xff00 at 2 flowid 1:10
#<63 byte ACK
tc filter add dev eth1 parent 1:0 protocol ip prio 10 u32 match ip protocol 6 0xff match u8 0x05 0x0f at 0 match u8 0x10 0xff at 33 match u16 0x0000 0xffc0 at 2 flowid 1:20
#<=128 byte ACK
tc filter add dev eth1 parent 1:0 protocol ip prio 11 u32 match ip protocol 6 0xff match u8 0x05 0x0f at 0 match u8 0x10 0xff at 33 match u16 0x0000 0xff00 at 2 flowid 1:30


tc filter add dev eth1 parent 1:0 protocol ip prio 12 handle 0x10 fw flowid 1:10
tc filter add dev eth1 parent 1:0 protocol ip prio 13 handle 0x20 fw flowid 1:20
tc filter add dev eth1 parent 1:0 protocol ip prio 14 handle 0x30 fw flowid 1:30
tc filter add dev eth1 parent 1:0 protocol ip prio 15 handle 0x40 fw flowid 1:40

#tc filter add dev eth1 parent 1:0 protocol ip prio 15 handle 0x10 fw flowid 1:40
#tc filter add dev eth1 parent 1:0 protocol ip prio 15 handle 0x40 fw flowid 1:40

tc qdisc add dev eth1 handle ffff: ingress
#tc filter add dev eth1 parent ffff: protocol ip prio 50 u32 match ip src 0.0.0.0/0 police rate ${DOWNMAX}kbit burst 200k drop flowid :1
#tc filter add dev eth1 parent ffff: protocol ip prio 50 u32 match ip src 0.0.0.0/0 police rate ${DOWNMAX}mbit buffer 400k drop flowid :1
tc filter add dev eth1 parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev ifb0

#tc qdisc add dev ifb0 root handle 1: fq_codel
#tc qdisc add dev ifb0 root handle 1: htb default 11
# Add root class HTB with rate limiting
#tc class add dev ifb0 parent 1: classid 1:1 htb rate ${DOWNMAX}mbit
#tc class add dev ifb0 parent 1:1 classid 1:11 htb rate ${DOWNMAX}mbit prio 0 burst 48k cburst 48k

tc qdisc add dev ifb0 root handle 1: tbf rate ${DOWNMAX}mbit burst 40k latency 30ms
tc qdisc add dev ifb0 parent 1: fq_codel

#shape inbound traffic
#tc qdisc add dev imq0 root handle 1: htb default 20
#tc class add dev imq0 parent 1: classid 1:1 htb rate \${DOWNMAX}kbit burst 15k
#tc class add dev imq0 parent 1:1 classid 1:10 htb rate 2500kbit ceil \${DOWNRATE}kbit mtu \${MTU} prio 1
#tc class add dev imq0 parent 1:1 classid 1:20 htb rate 2500kbit ceil \${DOWNRATE}kbit mtu \${MTU} prio 2
#tc qdisc add dev imq0 parent 1:10 handle 10: sfq perturb 10
#tc qdisc add dev imq0 parent 1:20 handle 20: sfq perturb 10
#tc filter add dev imq0 parent 1:0 protocol ip prio 12 handle 0x10 fw flowid 1:10
#tc filter add dev imq0 parent 1:0 protocol ip prio 13 handle 0x20 fw flowid 1:20

#tc filter add dev imq0 parent 1:10 protocol ip prio 50 u32 match ip src 0.0.0.0/0 police rate 4000kbit burst 10k drop flowid 1:10

#tc -s -d class show dev eth1
