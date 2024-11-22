#!/bin/bash

# Sicherer WireGuard-Server-Installer
# Gasic.bio v1.0 Konfiguration

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "Dieses Skript muss als root ausgeführt werden"
		exit 1
	fi
}

function checkVirt() {
	if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ wird nicht unterstützt"
		exit 1
	fi

	if [ "$(systemd-detect-virt)" == "lxc" ]; then
		echo "LXC wird nicht unterstützt (noch nicht)."
		echo "WireGuard kann technisch in einem LXC-Container laufen,"
		echo "aber das Kernelmodul muss auf dem Host installiert sein,"
		echo "der Container muss mit bestimmten Parametern gestartet werden"
		echo "und nur die Tools müssen im Container installiert werden."
		exit 1
	fi
}

function checkOS() {
	source /etc/os-release
	OS="${ID}"
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ ${VERSION_ID} -lt 10 ]]; then
			echo "Ihre Version von Debian (${VERSION_ID}) wird nicht unterstützt. Bitte verwenden Sie Debian 10 Buster oder neuer"
			exit 1
		fi
		OS=debian # überschreiben, wenn raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [[ ${RELEASE_YEAR} -lt 18 ]]; then
			echo "Ihre Version von Ubuntu (${VERSION_ID}) wird nicht unterstützt. Bitte verwenden Sie Ubuntu 18.04 oder neuer"
			exit 1
		fi
	elif [[ ${OS} == "fedora" ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			echo "Ihre Version von Fedora (${VERSION_ID}) wird nicht unterstützt. Bitte verwenden Sie Fedora 32 oder neuer"
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 7* ]]; then
			echo "Ihre Version von CentOS (${VERSION_ID}) wird nicht unterstützt. Bitte verwenden Sie CentOS 8 oder neuer"
			exit 1
		fi
	elif [[ -e /etc/oracle-release ]]; then
		source /etc/os-release
		OS=oracle
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "Es scheint, als ob Sie diesen Installer nicht auf einem Debian-, Ubuntu-, Fedora-, CentOS-, AlmaLinux-, Oracle- oder Arch-Linux-System ausführen"
		exit 1
	fi
}

function getHomeDirForClient() {
	local CLIENT_NAME=$1

	if [ -z "${CLIENT_NAME}" ]; then
		echo "Fehler: getHomeDirForClient() erfordert einen Clientnamen als Argument"
		exit 1
	fi

	# Home-Verzeichnis des Benutzers, in dem die Client-Konfiguration geschrieben wird
	if [ -e "/home/${CLIENT_NAME}" ]; then
		# wenn $1 ein Benutzername ist
		HOME_DIR="/home/${CLIENT_NAME}"
	elif [ "${SUDO_USER}" ]; then
		# wenn nicht, verwende SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# Wenn sudo als root ausgeführt wird
			HOME_DIR="/root"
		else
			HOME_DIR="/home/${SUDO_USER}"
		fi
	else
		# wenn nicht SUDO_USER, verwende /root
		HOME_DIR="/root"
	fi

	echo "$HOME_DIR"
}

function showProgress() {
	PID=$!
	spin='-\|/'
	i=0
	while kill -0 $PID 2>/dev/null; do
		i=$(( (i+1) % 4 ))
		printf "\r%s" "${spin:$i:1}"
		sleep .1
	done
}

function initialCheck() {
	isRoot
	checkVirt
	checkOS
}

function installQuestions() {
	echo "Willkommen beim WireGuard-Installer!"
	echo "Das Git-Repository ist verfügbar unter: https://github.com/kristiangasic"
	echo ""
	echo "Ich muss Ihnen ein paar Fragen stellen, bevor wir mit der Einrichtung beginnen."
	echo "Sie können die Standardeinstellungen beibehalten und einfach die Eingabetaste drücken, wenn Sie damit einverstanden sind."
	echo ""

	# Öffentliche IPv4- oder IPv6-Adresse erkennen und für den Benutzer vorausfüllen
	SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
	if [[ -z ${SERVER_PUB_IP} ]]; then
		# Öffentliche IPv6-Adresse erkennen
		SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	read -rp "Öffentliche IPv4- oder IPv6-Adresse: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

	# Öffentliches Interface erkennen und für den Benutzer vorausfüllen
	SERVER_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
	until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Öffentliches Interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
	done

	until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
		read -rp "WireGuard Interface-Name: " -e -i wg0 SERVER_WG_NIC
	done

	until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
		read -rp "Server WireGuard IPv4: " -e -i 10.66.66.1 SERVER_WG_IPV4
	done

	until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
		read -rp "Server WireGuard IPv6: " -e -i fd42:42:42::1 SERVER_WG_IPV6
	done

	# Zufallszahl innerhalb des privaten Portbereichs generieren
	RANDOM_PORT=$(shuf -i49152-65535 -n1)
	until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
		read -rp "Server WireGuard Port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
	done

	# Adguard DNS standardmäßig
	until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "Erster DNS-Resolver für die Clients: " -e -i 1.1.1.1 CLIENT_DNS_1
	done
	until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "Zweiter DNS-Resolver für die Clients (optional): " -e -i 1.0.0.1 CLIENT_DNS_2
		if [[ ${CLIENT_DNS_2} == "" ]]; then
			CLIENT_DNS_2="${CLIENT_DNS_1}"
		fi
	done

	until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
		echo -e "\nWireGuard verwendet einen Parameter namens AllowedIPs, um zu bestimmen, was über das VPN geroutet wird."
		read -rp "Liste der erlaubten IPs für generierte Clients (Standard lassen, um alles zu routen): " -e -i '0.0.0.0/0,::/0' ALLOWED_IPS
		if [[ ${ALLOWED_IPS} == "" ]]; then
			ALLOWED_IPS="0.0.0.0/0,::/0"
		fi
	done

	echo ""
	echo "Okay, das war alles, was ich brauchte. Wir sind bereit, Ihren WireGuard-Server jetzt einzurichten."
	echo "Sie können am Ende der Installation einen Client generieren."
	read -n1 -r -p "Drücken Sie eine beliebige Taste, um fortzufahren..."
}


function showProgress() {
	PID=$!
	spin='-\|/'
	i=0
	while kill -0 $PID 2>/dev/null; do
		i=$(( (i+1) % 4 ))
		printf "\r%s" "${spin:$i:1}"
		sleep .1
	done
}

function installWireGuard() {
	# Setup-Fragen zuerst ausführen
	installQuestions

	# WireGuard-Tools und Modul installieren
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
		apt-get update &
		showProgress
		wait
		apt-get install -y wireguard iptables resolvconf qrencode &
		showProgress
		wait
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
			echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
			apt-get update &
			showProgress
			wait
		fi
		apt update &
		showProgress
		wait
		apt-get install -y iptables resolvconf qrencode &
		showProgress
		wait
		apt-get install -y -t buster-backports wireguard &
		showProgress
		wait
	elif [[ ${OS} == 'fedora' ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			dnf install -y dnf-plugins-core &
			showProgress
			wait
			dnf copr enable -y jdoss/wireguard &
			showProgress
			wait
			dnf install -y wireguard-dkms &
			showProgress
			wait
		fi
		dnf install -y wireguard-tools iptables qrencode &
		showProgress
		wait
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 8* ]]; then
			yum install -y epel-release elrepo-release &
			showProgress
			wait
			yum install -y kmod-wireguard &
			showProgress
			wait
			yum install -y qrencode &
			showProgress
			wait
		fi
		yum install -y wireguard-tools iptables &
		showProgress
		wait
	elif [[ ${OS} == 'oracle' ]]; then
		dnf install -y oraclelinux-developer-release-el8 &
		showProgress
		wait
		dnf config-manager --disable -y ol8_developer &
		showProgress
		wait
		dnf config-manager --enable -y ol8_developer_UEKR6 &
		showProgress
		wait
		dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*' &
		showProgress
		wait
		dnf install -y wireguard-tools qrencode iptables &
		showProgress
		wait
	elif [[ ${OS} == 'arch' ]]; then
		pacman -S --needed --noconfirm wireguard-tools qrencode &
		showProgress
		wait
	fi

	# Sicherstellen, dass das Verzeichnis existiert (dies scheint auf Fedora nicht der Fall zu sein)
	mkdir /etc/wireguard >/dev/null 2>&1

	chmod 600 -R /etc/wireguard/

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	# WireGuard-Einstellungen speichern
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}" >/etc/wireguard/params

	# Server-Interface hinzufügen
	echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"

	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
		echo "PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	# Routing auf dem Server aktivieren
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf

	sysctl --system

	systemctl start "wg-quick@${SERVER_WG_NIC}"
	systemctl enable "wg-quick@${SERVER_WG_NIC}"

	newClient
	echo -e "${GREEN}Wenn Sie weitere Clients hinzufügen möchten, müssen Sie dieses Skript einfach ein weiteres Mal ausführen!${NC}"

	# Überprüfen, ob WireGuard läuft
	systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	WG_RUNNING=$?

	# WireGuard funktioniert möglicherweise nicht, wenn wir den Kernel aktualisiert haben. Benutzer auffordern, neu zu starten
	if [[ ${WG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}WARNUNG: WireGuard scheint nicht zu laufen.${NC}"
		echo -e "${ORANGE}Sie können überprüfen, ob WireGuard läuft mit: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
		echo -e "${ORANGE}Wenn Sie etwas wie \"Kann Gerät ${SERVER_WG_NIC} nicht finden\" erhalten, bitte neu starten!${NC}"
	else # WireGuard läuft
		echo -e "\n${GREEN}WireGuard läuft.${NC}"
		echo -e "${GREEN}Sie können den Status von WireGuard überprüfen mit: systemctl status wg-quick@${SERVER_WG_NIC}\n\n${NC}"
		echo -e "${ORANGE}Wenn Sie keine Internetverbindung von Ihrem Client haben, versuchen Sie, den Server neu zu starten.${NC}"
	fi
}

function newClient() {
	# Wenn SERVER_PUB_IP eine IPv6 ist, Klammern hinzufügen, falls sie fehlen
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
		if [[ ${SERVER_PUB_IP} != *"["* ]] || [[ ${SERVER_PUB_IP} != *"]"* ]]; then
			SERVER_PUB_IP="[${SERVER_PUB_IP}]"
		fi
	fi
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	echo ""
	echo "Client-Konfiguration"
	echo ""
	echo "Der Clientname muss aus alphanumerischen Zeichen bestehen. Er

 kann auch Unterstriche oder Bindestriche enthalten und darf 15 Zeichen nicht überschreiten."

	until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
		read -rp "Clientname: " -e CLIENT_NAME
		CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${CLIENT_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}Ein Client mit dem angegebenen Namen wurde bereits erstellt, bitte wählen Sie einen anderen Namen.${NC}"
			echo ""
		fi
	done

	for DOT_IP in {2..254}; do
		DOT_EXISTS=$(grep -c "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf")
		if [[ ${DOT_EXISTS} == '0' ]]; then
			break
		fi
	done

	if [[ ${DOT_EXISTS} == '1' ]]; then
		echo ""
		echo "Das konfigurierte Subnetz unterstützt nur 253 Clients."
		exit 1
	fi

	BASE_IP=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
	until [[ ${IPV4_EXISTS} == '0' ]]; do
		read -rp "Client WireGuard IPv4: ${BASE_IP}." -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV4="${BASE_IP}.${DOT_IP}"
		IPV4_EXISTS=$(grep -c "$CLIENT_WG_IPV4/32" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV4_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}Ein Client mit der angegebenen IPv4 wurde bereits erstellt, bitte wählen Sie eine andere IPv4.${NC}"
			echo ""
		fi
	done

	BASE_IP=$(echo "$SERVER_WG_IPV6" | awk -F '::' '{ print $1 }')
	until [[ ${IPV6_EXISTS} == '0' ]]; do
		read -rp "Client WireGuard IPv6: ${BASE_IP}::" -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV6="${BASE_IP}::${DOT_IP}"
		IPV6_EXISTS=$(grep -c "${CLIENT_WG_IPV6}/128" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV6_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}Ein Client mit der angegebenen IPv6 wurde bereits erstellt, bitte wählen Sie eine andere IPv6.${NC}"
			echo ""
		fi
	done

	# Schlüsselpaare für den Client generieren
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")

	# Client-Datei erstellen und den Server als Peer hinzufügen
	echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}" >"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# Den Client als Peer zum Server hinzufügen
	echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")

	# QR-Code generieren, wenn qrencode installiert ist
	if command -v qrencode &>/dev/null; then
		echo -e "${GREEN}\nHier ist Ihre Client-Konfigurationsdatei als QR-Code:\n${NC}"
		qrencode -t ansiutf8 -l L <"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
		echo ""
	fi

	echo -e "${GREEN}Ihre Client-Konfigurationsdatei befindet sich in ${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf${NC}"
}

function listClients() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo "Sie haben keine bestehenden Clients!"
		exit 1
	fi

	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
}

function revokeClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "Sie haben keine bestehenden Clients!"
		exit 1
	fi

	echo ""
	echo "Wählen Sie den bestehenden Client, den Sie widerrufen möchten"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Wählen Sie einen Client [1]: " CLIENT_NUMBER
		else
			read -rp "Wählen Sie einen Client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	# Die ausgewählte Nummer mit einem Clientnamen abgleichen
	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	# [Peer]-Block entfernen, der $CLIENT_NAME entspricht
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# Generierte Client-Datei entfernen
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	rm -f "${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# WireGuard neu starten, um Änderungen anzuwenden
	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
}

function uninstallWg() {
	echo ""
	echo -e "\n${RED}WARNUNG: Dies wird WireGuard deinstallieren und alle Konfigurationsdateien entfernen!${NC}"
	echo -e "${ORANGE}Bitte sichern Sie das Verzeichnis /etc/wireguard, wenn Sie Ihre Konfigurationsdateien behalten möchten.\n${NC}"
	read -rp "Möchten Sie WireGuard wirklich entfernen? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [[ $REMOVE == 'y' ]]; then
		checkOS

		systemctl stop "wg-quick@${SERVER_WG_NIC}"
		systemctl disable "wg-quick@${SERVER_WG_NIC}"

		if [[ ${OS} == 'ubuntu' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode &
			showProgress
			wait
		elif [[ ${OS} == 'debian' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode &
			showProgress
			wait
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y --noautoremove wireguard-tools qrencode &
			showProgress
			wait
			if [[ ${VERSION_ID} -lt 32 ]]; then
				dnf remove -y --noautoremove wireguard-dkms &
				showProgress
				wait
				dnf copr disable -y jdoss/wireguard &
				showProgress
				wait
			fi
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			yum remove -y --noautoremove wireguard-tools &
			showProgress
			wait
			if [[ ${VERSION_ID} == 8* ]]; then
				yum remove --noautoremove kmod-wireguard qrencode &
				showProgress
				wait
			fi
		elif [[ ${OS} == 'oracle' ]]; then
			yum remove --noautoremove wireguard-tools qrencode &
			showProgress
			wait
		elif [[ ${OS} == 'arch' ]]; then
			pacman -Rs --noconfirm wireguard-tools qrencode &
			showProgress
			wait
		fi

		rm -rf /etc/wireguard
		rm -f /etc/sysctl.d/wg.conf

		# sysctl neu laden
		sysctl --system

		# Überprüfen

, ob WireGuard läuft
		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
		WG_RUNNING=$?

		if [[ ${WG_RUNNING} -eq 0 ]]; then
			echo "WireGuard konnte nicht richtig deinstalliert werden."
			exit 1
		else
			echo "WireGuard wurde erfolgreich deinstalliert."
			exit 0
		fi
	else
		echo ""
		echo "Entfernung abgebrochen!"
	fi
}

function manageMenu() {
	echo "Willkommen bei WireGuard-install!"
	echo "Das Git-Repository ist verfügbar unter: https://github.com/kristiangasic"
	echo ""
	echo "Es sieht so aus, als wäre WireGuard bereits installiert."
	echo ""
	echo "Was möchten Sie tun?"
	echo "   1) Einen neuen Benutzer hinzufügen"
	echo "   2) Alle Benutzer auflisten"
	echo "   3) Bestehenden Benutzer widerrufen"
	echo "   4) WireGuard deinstallieren"
	echo "   5) Beenden"
	until [[ ${MENU_OPTION} =~ ^[1-5]$ ]]; do
		read -rp "Wählen Sie eine Option [1-5]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		newClient
		;;
	2)
		listClients
		;;
	3)
		revokeClient
		;;
	4)
		uninstallWg
		;;
	5)
		exit 0
		;;
	esac
}

# Überprüfen auf root, Virt, OS etc...
initialCheck

# Überprüfen, ob WireGuard bereits installiert ist und Parameter laden
if [[ -e /etc/wireguard/params ]]; then
	source /etc/wireguard/params
	manageMenu
else
	installWireGuard
fi
