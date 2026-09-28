#!/system/bin/sh
# Ferma forwarding e ripristina stato originale

IFACE=wlan0

# 1. Disabilita IP forwarding
echo 0 > /proc/sys/net/ipv4/ip_forward

# 2. Ripristina ICMP redirect
echo 1 > /proc/sys/net/ipv4/conf/all/send_redirects
echo 1 > /proc/sys/net/ipv4/conf/$IFACE/send_redirects

# 3. Ripristina rp_filter
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 1 > /proc/sys/net/ipv4/conf/$IFACE/rp_filter

# 4. Pulisci regole
iptables -F FORWARD 2>/dev/null
iptables -t nat -F POSTROUTING 2>/dev/null

echo "[-] MITM forwarding disattivato"