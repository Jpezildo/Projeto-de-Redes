import sys
import ipaddress
import socket
import logging
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, ICMP, TCP, Ether, ARP, conf, sr1, srp
from tabulate import tabulate
import re
import subprocess

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def varredura_icmp(ip, timeout):
    try:
        pacote = IP(dst=ip) / ICMP()
        resposta = sr1(pacote, timeout=timeout, verbose=0)
        if resposta:
            return ip
    except Exception:
        pass
    return None

def sonda_arp(ip, timeout):
    try:
        interface, _, _ = conf.route.route(ip)
        pacote = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        respostas, _ = srp(pacote, iface=interface, timeout=timeout, verbose=0)
        for _, pacote_recebido in respostas:
            if pacote_recebido.hwsrc:
                return pacote_recebido.hwsrc
    except Exception:
        pass
    return None


def consultar_cache_arp(ip):
    try:
        if sys.platform.startswith("win"):
            comando = f"C:\\Windows\\System32\\arp.exe -a {ip}"
            resultado = subprocess.check_output(comando, shell=True, text=True, errors="ignore")
            match = re.search(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})", resultado)
            if match:
                return match.group(0).replace("-", ":").lower()
        else:
            resultado = subprocess.check_output(f"ip neigh show {ip}", shell=True, text=True, errors="ignore")
            match = re.search(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", resultado)
            if match:
                return match.group(0).lower()
    except Exception:
        pass

    return None

def varredura_porta_syn(ip, porta, timeout):
    try:
        pacote = IP(dst=ip) / TCP(dport=porta, flags="S") 
        resposta = sr1(pacote, timeout=timeout, verbose=0)
        
        if resposta and resposta.haslayer(TCP):
            if resposta.getlayer(TCP).flags == 0x12:
                sr1(IP(dst=ip)/TCP(dport=porta, flags="R"), timeout=0.2, verbose=0)
                return porta
    except Exception:
        pass
    return None

def main():
    print("=" * 70)
    print(" 🛡️ NETPROBE WI-FI - MONITORAMENTO E CAPTURA DE PACOTES AO VIVO 🛡️")
    print("=" * 70)
    
    try:
        entrada_rede = input("[?] Digite a rede (Ex: 192.168.1.0/24) [Padrão: 192.168.1.0/24]: ").strip() or "192.168.1.0/24"
        rede = ipaddress.ip_network(entrada_rede, strict=False)
        
        timeout_ping = float(input("[?] Timeout de captura Ping/ARP (seg) [Padrão: 0.5]: ").strip() or "0.5")
        porta_ini = int(input("[?] Porta Inicial [Padrão: 20]: ").strip() or "20")
        porta_fim = int(input("[?] Porta Final [Padrão: 100]: ").strip() or "100")
    except ValueError:
        print("\n[!] Erro: Você digitou um valor inválido. Execução abortada com segurança.")
        sys.exit(1)

    if porta_ini > porta_fim:
        print("\n[!] Erro: A porta inicial deve ser menor ou igual à porta final.")
        sys.exit(1)

    print(f"\n[*] Iniciando captura na rede {rede}...")
    
    dispositivos_ativos = [] 
    ips_respondidos_icmp = set()

    print("[*] Passo 1: Disparando pacotes ICMP e capturando respostas...")
    with ThreadPoolExecutor(max_workers=50) as executor:
        tarefas = [executor.submit(varredura_icmp, str(ip), timeout_ping) for ip in rede.hosts()]
        for tarefa in tarefas:
            resultado = tarefa.result()
            if resultado:
                ips_respondidos_icmp.add(resultado)

    print("[*] Passo 2: Disparando pacotes ARP para contorno de firewall e vinculação MAC...")
    for ip in rede.hosts():
        ip_str = str(ip)
        mac_address = sonda_arp(ip_str, timeout_ping)
        
        if ip_str in ips_respondidos_icmp:
            mac_address = mac_address or consultar_cache_arp(ip_str)
            dispositivos_ativos.append({"ip": ip_str, "mac": mac_address or "Desconhecido", "status": "Online (ICMP)"})
        elif mac_address:
            dispositivos_ativos.append({"ip": ip_str, "mac": mac_address, "status": "Online (ARP)"})
        else:
            print(f"{ip_str} | Offline (sem resposta)", flush=True)
            continue

        dispositivo = dispositivos_ativos[-1]
        print(f"{ip_str} | {dispositivo['status']} | MAC: {dispositivo['mac']}", flush=True)

    print(f"[*] Passo 3: Realizando captura SYN-ACK para portas {porta_ini} a {porta_fim}...")
    tabela_final = []
    
    for disp in dispositivos_ativos:
        portas_abertas = []
        with ThreadPoolExecutor(max_workers=30) as executor:
            tarefas_portas = [executor.submit(varredura_porta_syn, disp["ip"], p, 0.3) for p in range(porta_ini, porta_fim + 1)]
            for t in tarefas_portas:
                porta_aberta = t.result()
                if porta_aberta:
                    portas_abertas.append(str(porta_aberta))
        
        str_portas = ", ".join(portas_abertas) if portas_abertas else "Nenhuma detectada"
        tabela_final.append([disp["ip"], disp["mac"], disp["status"], str_portas])

    print("\n" + "=" * 70)
    print("INVENTÁRIO DE REDE CONCLUÍDO")
    print("=" * 70)
    cabecalhos = ["IP", "Endereço MAC", "Status do Dispositivo", f"Portas ({porta_ini}-{porta_fim})"]
    print(tabulate(tabela_final, headers=cabecalhos, tablefmt="fancy_grid"))
    print("=" * 70)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Execução interrompida pelo usuário.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Erro fatal evitado. Causa: {e}")
        sys.exit(1)