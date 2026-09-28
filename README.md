# TermuxMitM 🐉

## 🇺🇸 | [🇮🇹](https://github.com/n0nexist/TermuxMitM#ITALIANO)

**Man-in-the-Middle attack on your Android phone.** 📱💀

A lightweight, from-scratch ARP spoofing tool written in C, designed to run
directly on rooted Android devices through Termux. It discovers live hosts
on your local subnet, poisons their ARP caches, and silently forwards
intercepted traffic to keep the victim's connection alive — turning your
phone into a transparent man-in-the-middle. 🕵️‍♂️

---

## ✨ Features

- 🔍 **Subnet scanning** — parallel ping sweep to discover live hosts on a `/24`
- 💉 **ARP cache poisoning** — bidirectional spoofing between victims and gateway
- 🎯 **Automatic MAC resolution** — no manual configuration of hardware addresses
- 🔀 **Traffic forwarding** — enables `ip_forward` and configures `iptables` so
  the victim's connection keeps working while traffic passes through you
- 🩹 **Graceful restore** — sends corrective ARP replies on exit to repair
  victim caches
- 📦 **Zero dependencies** — pure C with POSIX sockets, no external libraries

---

## 📋 Requirements

| Requirement | Notes |
| :--- | :--- |
| 📱 **Android device** | Rooted (Magisk or KernelSU) |
| 🖥️ **Termux** | Latest version from F-Droid or GitHub |
| 🔥 **`iptables`** | Install with `pkg install iptables` |
| 🧰 **`root-repo`** | Optional, for `tcpdump` and traffic inspection tools |
| ⚙️ **C compiler** | `clang` (install with `pkg install clang`) |

> ⚠️ **Legal notice** — This tool is intended for educational purposes and
> authorized penetration testing only. Using it on networks you do not own
> or have explicit permission to test is illegal in most jurisdictions. 🚨

---

## 🔨 Building

From Termux:

```bash
pkg install clang
clang -O2 -pthread -o universalMITM universalMitM.c
```

# TermuxMitM | ITALIANO 🐉

**Attacco Man-in-the-Middle sul tuo telefono Android.** 📱💀

Un tool leggero per ARP spoofing scritto da zero in C, progettato per girare
direttamente su dispositivi Android rootati tramite Termux. Scopre gli host
attivi sulla tua subnet locale, avvelena le loro cache ARP e inoltra
silenziosamente il traffico intercettato per mantenere viva la connessione
della vittima — trasformando il tuo telefono in un man-in-the-middle
trasparente. 🕵️‍♂️

---

## ✨ Funzionalità

- 🔍 **Scansione della subnet** — ping sweep parallelo per scoprire host attivi su una `/24`
- 💉 **ARP cache poisoning** — spoofing bidirezionale tra vittime e gateway
- 🎯 **Risoluzione MAC automatica** — nessuna configurazione manuale degli indirizzi hardware
- 🔀 **Inoltro del traffico** — abilita `ip_forward` e configura `iptables` in modo che
  la connessione della vittima continui a funzionare mentre il traffico passa da te
- 🩹 **Ripristino pulito** — invia ARP reply correttivi all'uscita per riparare
  le cache delle vittime
- 📦 **Zero dipendenze** — puro C con socket POSIX, nessuna libreria esterna

---

## 📋 Requisiti

| Requisito | Note |
| :--- | :--- |
| 📱 **Dispositivo Android** | Rootato (Magisk o KernelSU) |
| 🖥️ **Termux** | Ultima versione da F-Droid o GitHub |
| 🔥 **`iptables`** | Installa con `pkg install iptables` |
| 🧰 **`root-repo`** | Opzionale, per `tcpdump` e tool di ispezione del traffico |
| ⚙️ **Compilatore C** | `clang` (installa con `pkg install clang`) |

> ⚠️ **Avviso legale** — Questo tool è pensato per scopi educativi e
> penetration testing autorizzato. Usarlo su reti che non possiedi
> o per cui non hai esplicita autorizzazione è illegale nella maggior parte
> delle giurisdizioni. 🚨

---

## 🔨 Compilazione

Da Termux:

```bash
pkg install clang
clang -O2 -pthread -o universalMITM universalMitM.c
```
