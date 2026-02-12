#!/bin/bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

################################
# VALIDATE INPUT
################################
echo 1 > /proc/sys/net/ipv4/ip_forward

SERVER_ID="${1:-}"
INSTALL_TOKEN="${2:-}"

if [[ -z "$SERVER_ID" || -z "$INSTALL_TOKEN" ]]; then
  echo "Usage: bash $0 <server_id> <install_token>"
  exit 1
fi

################################
# SYSTEM PREP
################################
echo "[+] System prep..."

ln -fs /usr/share/zoneinfo/Asia/Manila /etc/localtime || true
timedatectl set-timezone Asia/Manila 2>/dev/null || true

apt update -y
apt upgrade -y

apt install -y \
  curl wget jq sudo git \
  openvpn easy-rsa \
  squid \
  iptables-persistent \
  certbot \
  python3

################################
# FETCH DOMAIN FROM API
################################
echo "[+] Fetching domain info..."

API_URL="https://apanel.mindfreak.online/api_formula/get_domain.php?server_id=${SERVER_ID}&token=${INSTALL_TOKEN}"
API_JSON="$(curl -fsSL "$API_URL")"

SUCCESS="$(echo "$API_JSON" | jq -r '.success')"
if [[ "$SUCCESS" != "true" ]]; then
  echo "API error: $API_JSON"
  exit 1
fi

API_ENDPOINT="$(echo "$API_JSON" | jq -r '.api_endpoint')"
AUTH_EMAIL="$(echo "$API_JSON" | jq -r '.email')"
AUTH_KEY="$(echo "$API_JSON" | jq -r '.key')"
ZONE_ID="$(echo "$API_JSON" | jq -r '.zone')"
DOMAIN_NAME="$(echo "$API_JSON" | jq -r '.domain')"

if [[ -z "$API_ENDPOINT" || -z "$AUTH_EMAIL" || -z "$AUTH_KEY" || -z "$ZONE_ID" || -z "$DOMAIN_NAME" ]]; then
  echo "API returned missing fields: $API_JSON"
  exit 1
fi

################################
# CREATE RANDOM SUBDOMAIN (A RECORD)
################################
echo "[+] Creating DNS record..."

IP_ADDRESS="$(curl -4fsS https://api.ipify.org || true)"
if [[ -z "$IP_ADDRESS" ]]; then
  IP_ADDRESS="$(curl -4fsS ipinfo.io/ip || true)"
fi
if [[ -z "$IP_ADDRESS" ]]; then
  echo "Failed to detect public IP"
  exit 1
fi

SUBDOMAIN="$(tr -dc a-z </dev/urandom | head -c5)"
FULL_DOMAIN="${SUBDOMAIN}.${DOMAIN_NAME}"

A_RECORD="$(cat <<EOF
{
  "type":"A",
  "name":"$FULL_DOMAIN",
  "content":"$IP_ADDRESS",
  "ttl":1,
  "proxied":false
}
EOF
)"

curl -fsS -X POST "${API_ENDPOINT%/}/${ZONE_ID}/dns_records" \
  -H "X-Auth-Email: $AUTH_EMAIL" \
  -H "X-Auth-Key: $AUTH_KEY" \
  -H "Content-Type: application/json" \
  --data "$A_RECORD" >/dev/null

mkdir -p /etc/ErwanScript
echo "$FULL_DOMAIN" > /etc/ErwanScript/domain

echo "[+] Waiting DNS propagation..."
sleep 10

################################
# LET'S ENCRYPT SSL (needs 80 free)
################################
echo "[+] Requesting SSL certificate..."

# Stop anything that might be using ports 80/443
systemctl stop ws-ovpn 2>/dev/null || true
systemctl stop squid 2>/dev/null || true
systemctl stop openvpn-server@tcp 2>/dev/null || true
systemctl stop openvpn-server@udp 2>/dev/null || true

fuser -k 80/tcp 2>/dev/null || true
fuser -k 443/tcp 2>/dev/null || true

certbot certonly --standalone \
  --preferred-challenges http \
  -d "$FULL_DOMAIN" \
  --non-interactive \
  --agree-tos \
  -m "admin@${DOMAIN_NAME}"

SSL_CERT="/etc/letsencrypt/live/$FULL_DOMAIN/fullchain.pem"
SSL_KEY="/etc/letsencrypt/live/$FULL_DOMAIN/privkey.pem"

if [[ ! -f "$SSL_CERT" || ! -f "$SSL_KEY" ]]; then
  echo "Let's Encrypt files not found"
  exit 1
fi

################################
# OPENVPN CERTS (your provided)
################################
echo "[+] Installing OpenVPN certificates..."

mkdir -p /etc/openvpn/certificates

cat >/etc/openvpn/certificates/ca.crt <<'EOF'
-----BEGIN CERTIFICATE-----
MIIDRTCCAi2gAwIBAgIUAlMg9LvhGott4Mj4H/mJV3kHq+YwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJS2FsZGFnLUNBMB4XDTI2MDIxMjExMTYyMVoXDTM2MDIx
MDExMTYyMVowFDESMBAGA1UEAwwJS2FsZGFnLUNBMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAskLhhtnFvfTHvb2U+Tm4vey8J0KDA1oD/krdF/SgoSEy
iLpQsz5doMgrH4zVGovlm+VNvbvogMo5mNwmOqQtrYcyzdaliSMTX4vRZAKmW0yN
VdfIPpTldp7C8WEzL6EkB6mu9V8fo6fjtwuyaLBzpPoYau7zMHt24jUbRgQJAKLs
wGH+HjfSY/+Klrm8v6SJ36/eZUzGBiXRMcsY0FTYrWL7A6+zzB6+ufc4lKAbKktC
RnthJ1lGBO57ENemhWXDwY7hZWzT84Rf3mD7tl2mVeGWuDuriRXtDcod7C7SQSsG
8FBdy9o87aQa6rUlVEOIwqX8T3OvpgdCNIRvCMVUpwIDAQABo4GOMIGLMAwGA1Ud
EwQFMAMBAf8wHQYDVR0OBBYEFM2a0lVDEKufyMK9NozxAT1ll4wnME8GA1UdIwRI
MEaAFM2a0lVDEKufyMK9NozxAT1ll4wnoRikFjAUMRIwEAYDVQQDDAlLYWxkYWct
Q0GCFAJTIPS74RqLbeDI+B/5iVd5B6vmMAsGA1UdDwQEAwIBBjANBgkqhkiG9w0B
AQsFAAOCAQEAI5yBFcPe6txV7+p+s/77cTXu4kD/Hs5M9QDuZuTEjwUGpjYbGr8+
5eH9nmTE2HbnU2kUdumVVlYfPOhx8mbJyNKWposhVPo/6ApXr9Nd+kcOuXZ7GtDp
9CKetaL1JB/u3hFL8/lGA85BEU0OEcpRNJBebGZ8o7BuP3y2ddb8XG109C53H+GV
b92ppj1heclaAUAL31EhpdNgnbjpLfPFzIqydpj5IL4J6boZcQa7llk7kSKZ0cXx
KhaleWptLCktnP2zlh/ZPdI6hAhEGCj4D61IFrjvrzfDK4PtWX4h4MdM4Jd+tHHd
3BzNyO52UoLQ3DegF+llHr832HuL0fzWuQ==
-----END CERTIFICATE-----
EOF

cat >/etc/openvpn/certificates/server.crt <<'EOF'
-----BEGIN CERTIFICATE-----
MIIDYzCCAkugAwIBAgIQJ+aBmAityIpoUriDpnq8iDANBgkqhkiG9w0BAQsFADAU
MRIwEAYDVQQDDAlLYWxkYWctQ0EwHhcNMjYwMjEyMTExNzU2WhcNMjgwNTE3MTEx
NzU2WjARMQ8wDQYDVQQDDAZzZXJ2ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQCjSqVp3SOBouuAs1THWFPGp0Y5B+/NYCCB1SMOPWKpiX3sPmx5mZwn
+27VHL1LswrbIYJVnH67aI6nCy+Am/UXObhTIGakW4UAa0D0pZY8G09ICJnZ5BkY
ZqWOcq0sVKe1PuUhkcwg6aZXtpBQzBR+tkQmDsazMi7yeDS9wd+uXsbsAoWmXHha
LlFHHOsrvRszWdLKCJIdmuLosC9Q2yZLdPkRahXkwIevheykdSa0OD+pTatiobxI
PnRjaRqfaCgXuUqjzRORgCGyqAThLlz8oc9Vz1z/hSeH32i0q1YbQ1iP2sbj1v7c
Z1CrcL5BoJrgMiF6ruS6BJNEnOLpx2BLAgMBAAGjgbMwgbAwCQYDVR0TBAIwADAd
BgNVHQ4EFgQUNbbiFSYwgpRUDbEFcEOYiRhgHpowTwYDVR0jBEgwRoAUzZrSVUMQ
q5/Iwr02jPEBPWWXjCehGKQWMBQxEjAQBgNVBAMMCUthbGRhZy1DQYIUAlMg9Lvh
Gott4Mj4H/mJV3kHq+YwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0PBAQDAgWg
MBEGA1UdEQQKMAiCBnNlcnZlcjANBgkqhkiG9w0BAQsFAAOCAQEABS+werVdfS3L
W5N4HJQi6nIFR09mcrZxuDLM7A7yN9Y/hhqy7bDN2VK8I2xhr9oh9IEQO4L6edYb
QO9Cj6/elV2xuF3ukwMT5vc4Um5T1dWh0dGzf9ik68O1Qp9NxOTWVLiDVX3Gms2m
1tEaUTdQKt/JKlSbUVfYRigroC8TyDbUE/8tkQd1FzuJi6SqUclEEgUwYzCQuUKc
bOQdEdvjTQTq+8pRcZBoyo/lCxdf3zl66uSiA8UBoAUaCzhsB+OrViOe2k53nBTc
gflmS/TdwhvAfzF+yKDu0xiZYyCi/sM8HI3MX+z9akhtZYsbbUC62ZkHd0CcW/u5
/pfEiF5gaQ==
-----END CERTIFICATE-----
EOF

cat >/etc/openvpn/certificates/server.key <<'EOF'
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCjSqVp3SOBouuA
s1THWFPGp0Y5B+/NYCCB1SMOPWKpiX3sPmx5mZwn+27VHL1LswrbIYJVnH67aI6n
Cy+Am/UXObhTIGakW4UAa0D0pZY8G09ICJnZ5BkYZqWOcq0sVKe1PuUhkcwg6aZX
tpBQzBR+tkQmDsazMi7yeDS9wd+uXsbsAoWmXHhaLlFHHOsrvRszWdLKCJIdmuLo
sC9Q2yZLdPkRahXkwIevheykdSa0OD+pTatiobxIPnRjaRqfaCgXuUqjzRORgCGy
qAThLlz8oc9Vz1z/hSeH32i0q1YbQ1iP2sbj1v7cZ1CrcL5BoJrgMiF6ruS6BJNE
nOLpx2BLAgMBAAECggEAAdG0P/D4ZfEXppENmICWd8FFyR84kpUpsPXFQ57goNzH
CD1UJbEC/u/5ry4d2Byj7squMFSQldGsJSz5FCbk4JSoCb9kxzna91nCEZ1Q/uvX
b+ryBjHCOoUCs6FyBHLEhPN0x62MnCjJglTi0JZxsD5I/uZeiUTFJkz3lqDl1Uft
ZbE0Kix/x5YSScM1MUHALihWWA1SOxxI4DmkdZ4HvJyeXmG+j94rp0zM25bEWa5E
R5zTlYzh5pPv4SH5AnWodSqsCFodYWt5Kx2vHqx5zsrVmaFp2d4On1LB2u+oqrt/
pAMl1yTdPLVfMfjxhPR3gkuZ640mwJfBUcwzzkoMAQKBgQDc3s8+glxZo0JOS5RM
QK0EbS0tWb8lRoqjXNckiW6FeZZNLWhqxdUuktwn9VvXxEM667GTP54IsgbCwUrJ
VeUiHi0yqnEKA9mjOZ7o1DBnh+m4wtYVjUqyJK6NnB0dpVd2TQRvxA7rY/30/C4b
fO4myidYhWFKMBaS6L535BneywKBgQC9Q2Ybd+sjzLaNzp+sx8sG4jVMSKOKY5Z7
WHluXpmxoZCSFp9TmYGVur2Yffo6EpjrlDgOEDSm5+i0OmzuoS6stWBxVargy83Y
z5GbY5g7Qr72kNg2icX170naVlASVPIQd9CofcqqObQjPIkazSiDs0VI93GXXqUk
hvpmrvrUgQKBgQCBwulRGTd2dkMTSrYCopDDo/zBwxNYq/vxhC7lyVREWK2kBARv
jnDzntZ3J2BhAG5bJHO8Rcjr5OOx8eulI7CtfbsiJB6rOp3Xlpe0xEz31lLK+LTc
DpmO1ZwzmD9G1ofu+cqcezwksSdXkfzoq1ojMesxx5LkCiKJBvI376v/RwKBgQCa
LmbnJ6jx8Bojqdjge56EzBEZRO+dlIWJlEjQRda1I2ZP7If9JcewP4Gm0bHgTzgu
af/ETSVndvNWp2YIfFw2rEeV7HEZUk4uOuJmkRr54+UHnnXU8CXJtRcX/EqctIDC
M6lTKa7JP9rk/bK/l7RSnd9qktIBu0OTXzZsIk4KgQKBgQC4QNHvHgMBQH9iIyhp
mSLmV3U7vAIoJOtFV0s7AjTLQ5ZGu/Apj4MOToXYxDpnA+MfvfmMqcCNXDtNIsD4
vp3UefcSAxZEfL4nYzJtVbd1vK92nu/BpuqEUedeiZPI316Cr+TvAeu5fT07qGmQ
t2ttOnnqWBAAnqVyjs6M53Y0qw==
-----END PRIVATE KEY-----
EOF

chmod 600 /etc/openvpn/certificates/server.key

################################
# OPENVPN (TCP 1194 + UDP 110) + PAM LINUX USERS
################################
echo "[+] Configuring OpenVPN (PAM Linux users)..."

PLUGIN="$(find /usr -name openvpn-plugin-auth-pam.so 2>/dev/null | head -n1 || true)"
if [[ -z "$PLUGIN" ]]; then
  echo "OpenVPN PAM plugin not found (openvpn-plugin-auth-pam.so)"
  exit 1
fi

mkdir -p /etc/openvpn/server

# PAM policy: restrict logins to users in vpnusers group (safer than allowing every system user)
groupadd -f vpnusers

cat >/etc/pam.d/openvpn <<'EOF'
auth    required   pam_succeed_if.so user ingroup vpnusers
auth    required   pam_unix.so nodelay

account required   pam_succeed_if.so user ingroup vpnusers
account required   pam_unix.so
EOF

COMMON_CFG="$(cat <<EOF
dev tun
user nobody
group nogroup

ca /etc/openvpn/certificates/ca.crt
cert /etc/openvpn/certificates/server.crt
key /etc/openvpn/certificates/server.key

# For your config style
dh none
topology subnet
server 10.10.0.0 255.255.255.0

keepalive 10 60
persist-key
persist-tun

verify-client-cert none
username-as-common-name
plugin $PLUGIN openvpn

duplicate-cn

# Compatibility (some clients)
tls-cipher DEFAULT:@SECLEVEL=0
tls-version-min 1.2
auth SHA256
data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC
data-ciphers-fallback AES-256-CBC

push "redirect-gateway def1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"

verb 3
EOF
)"

cat > /etc/openvpn/server/tcp.conf <<EOF
port 1194
proto tcp
$COMMON_CFG
EOF

cat > /etc/openvpn/server/udp.conf <<EOF
port 110
proto udp
$COMMON_CFG
EOF

systemctl enable --now openvpn-server@tcp
systemctl enable --now openvpn-server@udp
systemctl restart openvpn-server@tcp
systemctl restart openvpn-server@udp

################################
# WEBSOCKET (ONE PY FILE: WS 80 + WSS 443)
################################
echo "[+] Installing WS/WSS tunnel (Python asyncio)..."

cat >/usr/local/bin/ws-ovpn.py <<'PY'
#!/usr/bin/env python3
import asyncio
import ssl

OPENVPN_HOST = "127.0.0.1"
OPENVPN_PORT = 1194

WS_HOST = "0.0.0.0"
WS_PORT = 80

WSS_HOST = "0.0.0.0"
WSS_PORT = 443

CERT_FILE = "/etc/letsencrypt/live/FULLDOMAIN/fullchain.pem"
KEY_FILE  = "/etc/letsencrypt/live/FULLDOMAIN/privkey.pem"

RESPONSE = (
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"\r\n"
)

def is_ws_upgrade(data: bytes) -> bool:
    d = data.lower()
    if b"upgrade: websocket" not in d:
        return False
    # accept common variants
    if b"connection: upgrade" in d:
        return True
    if b"connection: keep-alive, upgrade" in d:
        return True
    return False

async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
    try:
        while True:
            chunk = await src.read(4096)
            if not chunk:
                break
            dst.write(chunk)
            await dst.drain()
    except:
        pass
    finally:
        try:
            dst.close()
        except:
            pass

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        data = await reader.read(2048)
        if not data or not is_ws_upgrade(data):
            writer.close()
            return

        writer.write(RESPONSE)
        await writer.drain()

        ovpn_reader, ovpn_writer = await asyncio.open_connection(OPENVPN_HOST, OPENVPN_PORT)

        await asyncio.gather(
            pipe(reader, ovpn_writer),
            pipe(ovpn_reader, writer)
        )
    except:
        try:
            writer.close()
        except:
            pass

async def main():
    # WS server
    ws_server = await asyncio.start_server(handle_client, WS_HOST, WS_PORT)

    # WSS server
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    wss_server = await asyncio.start_server(handle_client, WSS_HOST, WSS_PORT, ssl=ctx)

    async with ws_server, wss_server:
        await asyncio.gather(ws_server.serve_forever(), wss_server.serve_forever())

if __name__ == "__main__":
    asyncio.run(main())
PY

# Patch FULLDOMAIN in python file
sed -i "s|FULLDOMAIN|$FULL_DOMAIN|g" /usr/local/bin/ws-ovpn.py
chmod +x /usr/local/bin/ws-ovpn.py

cat >/etc/systemd/system/ws-ovpn.service <<EOF
[Unit]
Description=OpenVPN WS/WSS Tunnel (WS:80 + WSS:443 -> 127.0.0.1:1194)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/ws-ovpn.py
Restart=always
RestartSec=2
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ws-ovpn
systemctl restart ws-ovpn

################################
# SQUID (8080 only)
################################
echo "[+] Configuring Squid..."

cat >/etc/squid/squid.conf <<'EOF'
http_port 8080

# Allow VPN subnet only
acl vpn src 10.10.0.0/24
http_access allow vpn
http_access deny all

dns_nameservers 1.1.1.1 8.8.8.8
visible_hostname vpn-server

via off
forwarded_for off
EOF

systemctl enable --now squid
systemctl restart squid

################################
# FIREWALL / NAT
################################
echo "[+] Configuring iptables..."

IFACE="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
if [[ -z "$IFACE" ]]; then
  echo "Failed to detect interface for NAT"
  exit 1
fi

# Flush (be careful if you have existing firewall rules)
iptables -F
iptables -t nat -F

iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Allow required ports
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 1194 -j ACCEPT
iptables -A INPUT -p udp --dport 110 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT

# NAT VPN subnet
iptables -A FORWARD -s 10.10.0.0/24 -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o "$IFACE" -j MASQUERADE

iptables-save > /etc/iptables/rules.v4
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

################################
# FINISH
################################
echo ""
echo "=================================="
echo "VPN INSTALL COMPLETE"
echo "Domain: $FULL_DOMAIN"
echo "IP: $IP_ADDRESS"
echo "TCP 1194 | UDP 110 | WS 80 | WSS 443 | Squid 8080"
echo ""
echo "Create VPN users (Linux PAM):"
echo "  groupadd -f vpnusers"
echo "  useradd -M -s /usr/sbin/nologin -G vpnusers USERNAME"
echo "  passwd USERNAME"
echo "Delete user:"
echo "  userdel USERNAME"
echo "=================================="

echo "[+] Listening ports:"
ss -lntup | grep -E ':(1194|110|80|443|8080)\b' || true
