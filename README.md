# 🔐 WireGuard Secure Server Installer

Dieses Skript automatisiert die Installation, Konfiguration und Verwaltung eines **WireGuard**-VPN-Servers auf verschiedenen Linux-Distributionen. Es bietet eine benutzerfreundliche Möglichkeit, einen sicheren VPN-Server mit minimalem Aufwand einzurichten.

---

## 🛠️ Features
- **Automatische Installation und Konfiguration** von WireGuard.
- Unterstützung für die meisten Linux-Distributionen (Debian, Ubuntu, Fedora, CentOS, AlmaLinux, Oracle Linux, Arch Linux).
- **Benutzerverwaltung**: Hinzufügen, Auflisten und Entfernen von Clients.
- **Automatische Firewall- und Routing-Konfiguration**.
- **QR-Code-Generierung** für einfache Client-Konfiguration.
- **Deinstallationsoption**, um alle Konfigurationsdateien zu entfernen.

---

## 📋 Voraussetzungen
- Root-Zugriff auf einen Linux-Server.
- Unterstützte Linux-Distribution (Debian 10+, Ubuntu 18.04+, Fedora 32+, CentOS 8+, Arch Linux).
- Ein öffentlich zugänglicher Server mit einer IPv4- oder IPv6-Adresse.

---

## 📖 Installation und Nutzung

1. **Repository klonen:**
   ```bash
   git clone https://github.com/kristiangasic/wireguard.git
   cd wireguard
   ```

2. **Das Skript ausführbar machen:**
   ```bash
   chmod +x wg-install.sh
   ```

3. **Das Skript ausführen:**
   ```bash
   sudo ./wg-install.sh
   ```

4. **Installation abschließen:**
   Folgen Sie den Anweisungen auf dem Bildschirm, um WireGuard einzurichten.

---

## 🧑‍💻 Verwaltung

Nach der Installation kann das Skript für die Verwaltung des WireGuard-Servers erneut ausgeführt werden:
```bash
sudo ./wg-install.sh
```

### Verfügbare Optionen:
1. **Neuen Client hinzufügen**: Generiert eine neue Client-Konfigurationsdatei und zeigt einen QR-Code an.
2. **Alle Clients auflisten**: Zeigt alle registrierten Clients an.
3. **Client widerrufen**: Entfernt einen Client und widerruft dessen Zugriff.
4. **WireGuard deinstallieren**: Entfernt WireGuard und alle zugehörigen Konfigurationen.

---

## 📋 Unterstützte Distributionen
- **Debian** (10+)
- **Ubuntu** (18.04+)
- **Fedora** (32+)
- **CentOS** (8+)
- **AlmaLinux** (8+)
- **Oracle Linux** (8+)
- **Arch Linux**

---

## 🛡️ Sicherheit
- Standardmäßig werden DNS-Resolver von Cloudflare verwendet (1.1.1.1, 1.0.0.1).
- Unterstützt IPv4 und IPv6.
- Zufällige Ports und sichere Schlüsselgenerierung.

---

## 📝 Hinweise
- Das Skript unterstützt keine Virtualisierungsumgebungen wie **OpenVZ** oder **LXC**, da spezielle Kernelmodule erforderlich sind.
- DNS- und Firewall-Einstellungen müssen vor der Nutzung korrekt konfiguriert werden.

---

## 📬 Support
Für Fragen oder Unterstützung:  
📧 **kristian@gasic.bio**

---

## 📚 Ressourcen
- [WireGuard Dokumentation](https://www.wireguard.com/)
- [GitHub Repository](https://github.com/kristiangasic/wireguard)

[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/kristiangasic)

---
