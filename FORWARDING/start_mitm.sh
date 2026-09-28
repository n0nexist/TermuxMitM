#!/system/bin/sh
# Avvia forwarding per MITM su stessa interfaccia

IFACE=wlan0
GATEWAY=192.168.43.1      # IP del PC (hotspot) - ADATTA

# 1. Abilita IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# 2. Disabilita ICMP redirect (CRUCIALE)
#    Se attivi, il kernel dice a TEL2 "vai diretto al PC", rompendo il MITM
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
echo 0 > /proc/sys/net/ipv4/conf/$IFACE/send_redirects

# 3. Disabilita reverse path filtering (evita drop di pacchetti)
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/$IFACE/rp_filter

# 4. Pulisci regole vecchie
iptables -F FORWARD 2>/dev/null
iptables -t nat -F POSTROUTING 2>/dev/null

# 5. Permetti forwarding tra TEL2 e PC (stessa interfaccia)
#    Non serve -i/-o specifici perché è tutto su wlan0
iptables -A FORWARD -i $IFACE -o $IFACE -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -P FORWARD ACCEPT

echo "[+] MITM forwarding attivo su $IFACE"