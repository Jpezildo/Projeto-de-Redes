import socket
from scapy.all import DNS, DNSQR, DNSRR

IP_RESPOSTA_DEMO = input("[?] Digite o IPv4 da Máquina B na rede Wi-Fi (ex: 192.168.0.0): ").strip()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((IP_RESPOSTA_DEMO, 53))
print(f"[*] Servidor DNS ativo em {IP_RESPOSTA_DEMO}:53 (UDP) — Resolvendo 'demo.lab' -> {IP_RESPOSTA_DEMO}")

while True:
    dados, endereco_cliente = sock.recvfrom(1024)
    pkt = DNS(dados)
    if pkt.qr == 0 and pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".").lower()
        print(f"[DNS] Consulta de {endereco_cliente[0]}:{endereco_cliente[1]} -> {qname} (ID={pkt.id})")

        if qname == "demo.lab":
            resposta = DNS(
                id=pkt.id,
                qr=1,
                aa=1,
                rd=pkt.rd,
                ra=1,
                rcode=0,  # NOERROR
                qd=pkt.qd,
                an=DNSRR(rrname=pkt[DNSQR].qname, type="A", ttl=60, rdata=IP_RESPOSTA_DEMO),
            )
        else:
            resposta = DNS(
                id=pkt.id,
                qr=1,
                aa=1,
                rd=pkt.rd,
                ra=1,
                rcode=3,  # NXDOMAIN
                qd=pkt.qd,
            )
        sock.sendto(bytes(resposta), endereco_cliente)