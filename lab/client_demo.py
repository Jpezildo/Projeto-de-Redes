import socket
import time
from scapy.all import DNS, DNSQR, DNSRR

IP_SERVIDOR_B = input("[?] Digite o IPv4 da Máquina B (Servidor DNS/HTTP): ").strip()


def consultar_dns(dominio: str, ip_dns: str) -> str:
    pkt = DNS(id=0x1234, rd=1, qd=DNSQR(qname=dominio, qtype="A"))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(3.0)
        s.sendto(bytes(pkt), (ip_dns, 53))
        dados, _ = s.recvfrom(1024)
        resp = DNS(dados)
        if resp.rcode == 0 and resp.haslayer(DNSRR):
            ip_resolvido = resp[DNSRR].rdata
            print(f"[Cliente A] DNS OK: {dominio} -> {ip_resolvido} (Transaction ID: {resp.id})")
            return ip_resolvido
    raise RuntimeError(f"Falha ao resolver {dominio}")


def enviar_http(ip_destino: str, requisicao_raw: bytes) -> None:
    with socket.create_connection((ip_destino, 80), timeout=3.0) as s:
        s.sendall(requisicao_raw)
        resposta = s.recv(4096).decode("utf-8", errors="replace")
        primeira_linha = resposta.splitlines()[0] if resposta else "Sem resposta"
        print(f"[Cliente A] Resposta HTTP: {primeira_linha}")


if __name__ == "__main__":
    ip_alvo = consultar_dns("demo.lab", IP_SERVIDOR_B)
    time.sleep(0.5)

    req_get = (
        b"GET / HTTP/1.1\r\n"
        b"Host: demo.lab\r\n"
        b"User-Agent: NetProbe-LabClient/1.0\r\n"
        b"Connection: close\r\n\r\n"
    )
    enviar_http(ip_alvo, req_get)
    time.sleep(0.5)

    corpo_post = b"aluno=JoaoPedro&disciplina=Redes&teste=POST_ECHO"
    req_post = (
        b"POST /echo HTTP/1.1\r\n"
        b"Host: demo.lab\r\n"
        b"User-Agent: NetProbe-LabClient/1.0\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        + f"Content-Length: {len(corpo_post)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
        + corpo_post
    )
    enviar_http(ip_alvo, req_post)