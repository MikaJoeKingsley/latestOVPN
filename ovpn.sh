#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

################################

# INPUT CHECK

################################

echo 1 > /proc/sys/net/ipv4/ip_forward

SERVER_ID="$1"
INSTALL_TOKEN="$2"

if [[ -z "$SERVER_ID" || -z "$INSTALL_TOKEN" ]]; then
echo "Usage: bash install.sh <server_id> <token>"
exit 1
fi

################################

# SYSTEM PREP

################################

echo "[+] Installing packages..."

apt update -y
apt install -y curl wget jq sudo git openvpn squid stunnel4 iptables-persistent certbot python3

sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4 || true

################################

# FETCH DOMAIN

################################

echo "[+] Fetching domain..."

API_URL="https://apanel.mindfreak.online/api_formula/get_domain.php?server_id=${SERVER_ID}&token=${INSTALL_TOKEN}"
API_JSON="$(curl -fsSL "$API_URL")"

SUCCESS="$(echo "$API_JSON" | jq -r '.success')"
[ "$SUCCESS" != "true" ] && echo "API error" && exit 1

API_ENDPOINT="$(echo "$API_JSON" | jq -r '.api_endpoint')"
AUTH_EMAIL="$(echo "$API_JSON" | jq -r '.email')"
AUTH_KEY="$(echo "$API_JSON" | jq -r '.key')"
ZONE_ID="$(echo "$API_JSON" | jq -r '.zone')"
DOMAIN_NAME="$(echo "$API_JSON" | jq -r '.domain')"

################################
# CREATE RANDOM SUBDOMAIN
################################

echo "[+] Creating DNS record..."

IP_ADDRESS=$(curl -4s ipinfo.io/ip)
SUBDOMAIN=$(tr -dc a-z </dev/urandom | head -c5)
FULL_DOMAIN="${SUBDOMAIN}.${DOMAIN_NAME}"

A_RECORD=$(cat <<EOF
{
"type":"A",
"name":"$FULL_DOMAIN",
"content":"$IP_ADDRESS",
"ttl":1,
"proxied":false
}
EOF
)

curl -s -X POST "$API_ENDPOINT/$ZONE_ID/dns_records" \
-H "X-Auth-Email: $AUTH_EMAIL" \
-H "X-Auth-Key: $AUTH_KEY" \
-H "Content-Type: application/json" \
--data "$A_RECORD"

mkdir -p /etc/ErwanScript
echo "$FULL_DOMAIN" > /etc/ErwanScript/domain

echo "[+] Waiting DNS propagation..."
sleep 10
done

################################

# SSL CERT

################################

echo "[+] Requesting SSL..."

systemctl stop ws-ovpn squid openvpn-server@tcp openvpn-server@udp 2>/dev/null || true
fuser -k 80/tcp 443/tcp 2>/dev/null || true

certbot certonly --standalone 
--preferred-challenges http 
-d "$FULL_DOMAIN" 
--non-interactive 
--agree-tos 
-m "admin@${DOMAIN_NAME}"

SSL_CERT="/etc/letsencrypt/live/$FULL_DOMAIN/fullchain.pem"
SSL_KEY="/etc/letsencrypt/live/$FULL_DOMAIN/privkey.pem"

if [ ! -f "$SSL_CERT" ]; then
echo "SSL certificate failed!"
exit 1
fi

################################

# OPENVPN CERTIFICATES

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

PLUGIN="$(find /usr -name openvpn-plugin-auth-pam.so | head -n1)"

cat >/etc/pam.d/openvpn <<EOF
auth required pam_unix.so
account required pam_unix.so
EOF

COMMON_CFG=$(cat <<EOF
dev tun
user nobody
group nogroup
ca /etc/openvpn/certificates/ca.crt
cert /etc/openvpn/certificates/server.crt
key /etc/openvpn/certificates/server.key
dh none
topology subnet
server 10.10.0.0 255.255.255.0
plugin $PLUGIN openvpn
duplicate-cn
tls-version-min 1.2
auth SHA256
cipher AES-256-CBC
push "redirect-gateway def1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
verb 3
EOF
)

mkdir -p /etc/openvpn/server

echo -e "port 1194\nproto tcp\n$COMMON_CFG" > /etc/openvpn/server/tcp.conf
echo -e "port 1198\nproto udp\n$COMMON_CFG" > /etc/openvpn/server/udp.conf

systemctl enable openvpn-server@tcp
systemctl enable openvpn-server@udp

################################

# STUNNEL SSL 442

################################

cat >/etc/stunnel/stunnel.conf <<EOF
foreground = no
cert = $SSL_CERT
key = $SSL_KEY

[openvpn]
accept = 442
connect = 127.0.0.1:1194
EOF

systemctl enable stunnel4

################################

# WEBSOCKET 80 + 443

################################

cat >/usr/local/bin/ws-ovpn.py <<PY
#!/usr/bin/env python3
import asyncio, ssl

async def pipe(a,b):
try:
while True:
d = await a.read(4096)
if not d: break
b.write(d)
await b.drain()
except: pass

async def handler(r,w):
d = await r.read(2048)
if b"websocket" not in d.lower():
w.close()
return

```
w.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
await w.drain()

rr,ww = await asyncio.open_connection("127.0.0.1",1194)
await asyncio.gather(pipe(r,ww),pipe(rr,w))
```

async def main():
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("$SSL_CERT","$SSL_KEY")

```
s1 = await asyncio.start_server(handler,"0.0.0.0",80)
s2 = await asyncio.start_server(handler,"0.0.0.0",443,ssl=ctx)

async with s1,s2:
    await asyncio.gather(s1.serve_forever(),s2.serve_forever())
```

asyncio.run(main())
PY

chmod +x /usr/local/bin/ws-ovpn.py

cat >/etc/systemd/system/ws-ovpn.service <<EOF
[Unit]
Description=WebSocket OpenVPN
After=network.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/ws-ovpn.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ws-ovpn

################################

# SQUID PROXY

################################

cat >/etc/squid/squid.conf <<EOF
http_port 8080
http_port 8000
acl vpn src 10.10.0.0/24
http_access allow vpn
http_access deny all
via off
forwarded_for off
EOF

systemctl enable squid

################################

# FIREWALL

################################

IFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')

iptables -F
iptables -t nat -F

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

for p in 22 80 442 443 1194 8080 8000; do
iptables -A INPUT -p tcp --dport $p -j ACCEPT
done

iptables -A INPUT -p udp --dport 1198 -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o $IFACE -j MASQUERADE

iptables-save > /etc/iptables/rules.v4

################################

# START SERVICES

################################

systemctl restart openvpn-server@tcp
systemctl restart openvpn-server@udp
systemctl restart stunnel4
systemctl restart ws-ovpn
systemctl restart squid

################################

# DONE

################################

echo "============================"
echo "INSTALL COMPLETE"
echo "Domain: $FULL_DOMAIN"
echo "TCP 1194 | UDP 1198"
echo "WS 80 | WSS 443"
echo "SSL 442"
echo "Squid 8080/8000"
echo "============================"
