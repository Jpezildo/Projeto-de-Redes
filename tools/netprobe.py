import os
import re
import sys
import ctypes
import socket
import logging
import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor

# Garante que a pasta raiz (Projeto-de-Redes) esteja no sys.path antes de importar 'src'
RAIZ_PROJETO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if RAIZ_PROJETO not in sys.path:
    sys.path.insert(0, RAIZ_PROJETO)

from scapy.all import IP, ICMP, TCP, Ether, ARP, sr, srp, send, conf, get_if_hwaddr
from tabulate import tabulate

from src.sniffer import iniciar_sniffer, listar_interfaces

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def verificar_privilegios() -> bool:
    """Verifica se o processo possui privilégios de Administrador (Windows) ou Root (Linux/macOS)."""
    if sys.platform.startswith("win"):
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def obter_ip_e_mac_locais() -> tuple[str | None, str | None]:
    """Descobre o IPv4 ativo e o endereço MAC da interface local."""
    ip_local = None
    mac_local = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip_local = s.getsockname()[0]
    except Exception:
        pass

    try:
        mac = get_if_hwaddr(conf.iface)
        if mac and mac != "00:00:00:00:00:00":
            mac_local = mac.lower()
    except Exception:
        pass

    return ip_local, mac_local


def varredura_icmp_lote(hosts: list[str], timeout: float) -> set[str]:
    """Envia pacotes ICMP Echo Request em lote único via sr()."""
    respondidos = set()
    try:
        pacotes = [IP(dst=ip) / ICMP() for ip in hosts]
        respostas, _ = sr(pacotes, timeout=timeout, inter=0.002, verbose=0)
        for _, recebido in respostas:
            if recebido.haslayer(ICMP) and recebido.getlayer(ICMP).type == 0:
                respondidos.add(recebido[IP].src)
    except Exception:
        pass
    return respondidos


def varredura_arp_lote(rede_str: str, timeout: float) -> dict[str, str]:
    """Envia ARP broadcast para toda a sub-rede de uma única vez."""
    mapa_ip_mac = {}
    try:
        pacote = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=rede_str)
        respostas, _ = srp(pacote, timeout=timeout, verbose=0)
        for _, pacote_recebido in respostas:
            if pacote_recebido.psrc and pacote_recebido.hwsrc:
                mapa_ip_mac[pacote_recebido.psrc] = pacote_recebido.hwsrc.lower()
    except Exception:
        pass
    return mapa_ip_mac


def consultar_cache_arp_so(ip: str) -> str | None:
    """Fallback que consulta a tabela ARP local do sistema operacional."""
    try:
        if sys.platform.startswith("win"):
            comando = ["C:\\Windows\\System32\\arp.exe", "-a", ip]
            resultado = subprocess.check_output(comando, text=True, errors="ignore")
            match = re.search(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})", resultado)
            if match:
                return match.group(0).replace("-", ":").lower()
        else:
            comando = ["ip", "neigh", "show", ip]
            resultado = subprocess.check_output(comando, text=True, errors="ignore")
            match = re.search(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", resultado)
            if match:
                return match.group(0).lower()
    except Exception:
        pass
    return None


def varredura_portas_syn_lote(ip: str, porta_ini: int, porta_fim: int, timeout: float) -> list[int]:
    """Executa TCP SYN Scan (Half-Open) em lote único para toda a faixa de portas."""
    abertas = []
    try:
        portas = list(range(porta_ini, porta_fim + 1))
        pacotes = IP(dst=ip) / TCP(dport=portas, flags="S")
        respostas, _ = sr(pacotes, timeout=timeout, inter=0.001, verbose=0)

        for _, recebido in respostas:
            if recebido.haslayer(TCP) and recebido.getlayer(TCP).flags == 0x12:
                porta_aberta = recebido.getlayer(TCP).sport
                abertas.append(porta_aberta)
                send(IP(dst=ip) / TCP(dport=porta_aberta, flags="R"), verbose=0)
    except Exception:
        pass
    return sorted(set(abertas))


def varredura_porta_local(ip: str, porta: int, timeout: float) -> int | None:
    """Verifica uma porta TCP no próprio host via socket TCP Connect."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, porta)) == 0:
                return porta
    except Exception:
        pass
    return None


def varredura_portas_locais(ip: str, porta_ini: int, porta_fim: int) -> list[int]:
    """Varre portas TCP no próprio host utilizando sockets nativos."""
    abertas = []
    with ThreadPoolExecutor(max_workers=60) as executor:
        tarefas = [
            executor.submit(varredura_porta_local, ip, p, 0.15)
            for p in range(porta_ini, porta_fim + 1)
        ]
        for t in tarefas:
            res = t.result()
            if res:
                abertas.append(res)
    return sorted(abertas)


def executar_inventario() -> None:
    """Executa o fluxo completo de descoberta de dispositivos e varredura de portas."""
    ip_local, mac_local = obter_ip_e_mac_locais()
    rede_sugerida = "192.168.1.0/24"
    if ip_local:
        partes = ip_local.split(".")
        if len(partes) == 4:
            rede_sugerida = f"{partes[0]}.{partes[1]}.{partes[2]}.0/24"

    try:
        entrada_rede = (
            input(f"[?] Digite a rede (Ex: {rede_sugerida}) [Padrão: {rede_sugerida}]: ").strip()
            or rede_sugerida
        )
        rede = ipaddress.ip_network(entrada_rede, strict=False)

        timeout_ping = float(
            input("[?] Timeout de captura Ping/ARP (seg) [Padrão: 1.0]: ").strip() or "1.0"
        )
        porta_ini = int(input("[?] Porta Inicial [Padrão: 20]: ").strip() or "20")
        porta_fim = int(input("[?] Porta Final [Padrão: 100]: ").strip() or "100")
        mostrar_offline = (
            input("[?] Exibir também IPs offline na tabela? (s/N) [Padrão: N]: ").strip().lower()
            == "s"
        )

        if porta_ini < 1 or porta_fim > 65535 or porta_ini > porta_fim:
            raise ValueError("Faixa de portas inválida.")
    except ValueError as err:
        print(f"\n[!] Erro de entrada: {err}. Operação cancelada.")
        return

    print(f"\n[*] Iniciando inventário na rede {rede}...")
    hosts_rede = [str(ip) for ip in rede.hosts()]

    print("[*] Passo 1: Disparando pacotes ICMP (Ping Sweep)...")
    ips_respondidos_icmp = varredura_icmp_lote(hosts_rede, timeout_ping)

    print("[*] Passo 2: Disparando sonda ARP em lote para contorno de firewall e vínculo IP/MAC...")
    
    mapa_mac = varredura_arp_lote(str(rede), timeout_ping)

    dispositivos_ativos = []
    dispositivos_offline = []

    for ip_str in hosts_rede:
        mac_address = mapa_mac.get(ip_str) or consultar_cache_arp_so(ip_str)

        if ip_str == ip_local:
            dispositivos_ativos.append(
                {
                    "ip": ip_str,
                    "mac": mac_local or mac_address or "Interface Local",
                    "status": "Online (Host Local)",
                }
            )
        elif ip_str in ips_respondidos_icmp:
            dispositivos_ativos.append(
                {
                    "ip": ip_str,
                    "mac": mac_address or "Desconhecido (Roteado)",
                    "status": "Online (ICMP)",
                }
            )
        elif mac_address:
            dispositivos_ativos.append(
                {
                    "ip": ip_str,
                    "mac": mac_address,
                    "status": "Online (ARP)",
                }
            )
        else:
            dispositivos_offline.append(
                {
                    "ip": ip_str,
                    "mac": "-",
                    "status": "Sem resposta",
                }
            )

    print(
        f"[*] Passo 3: Varrendo portas TCP ({porta_ini} a {porta_fim}) "
        f"em {len(dispositivos_ativos)} dispositivo(s) ativo(s)..."
    )
    tabela_final = []

    for disp in dispositivos_ativos:
        if disp["ip"] == ip_local:
            portas_abertas = varredura_portas_locais(disp["ip"], porta_ini, porta_fim)
        else:
            portas_abertas = varredura_portas_syn_lote(disp["ip"], porta_ini, porta_fim, 0.8)

        str_portas = ", ".join(map(str, portas_abertas)) if portas_abertas else "Nenhuma detectada"
        tabela_final.append([disp["ip"], disp["mac"], disp["status"], str_portas])

    if mostrar_offline:
        for disp in dispositivos_offline:
            tabela_final.append([disp["ip"], disp["mac"], disp["status"], "-"])

    print("\n" + "=" * 78)
    print(
        f" INVENTÁRIO DE REDE CONCLUÍDO ({len(dispositivos_ativos)} Online / {len(dispositivos_offline)} Sem resposta)"
    )
    print("=" * 78)
    cabecalhos = ["IP", "Endereço MAC", "Status do Dispositivo", f"Portas ({porta_ini}-{porta_fim})"]
    print(tabulate(tabela_final, headers=cabecalhos, tablefmt="fancy_grid"))
    print("=" * 78)


def executar_modulo_sniffer() -> None:
    """Configura e inicia a captura de tráfego HTTP e DNS."""
    ip_local, _ = obter_ip_e_mac_locais()
    interfaces = listar_interfaces()
    indice_wifi_padrao = None

    if interfaces:
        print("\n[*] Interfaces de rede detectadas:")
        for idx, item in enumerate(interfaces):
            descricao = item[1] if isinstance(item, tuple) else str(item)
            marcador = ""
            if ip_local and ip_local in descricao:
                indice_wifi_padrao = idx
                marcador = "  <-- [DETECTADA COMO ATIVA]"
            print(f"    [{idx}] {descricao}{marcador}")

    texto_padrao = f"Padrão: {indice_wifi_padrao}" if indice_wifi_padrao is not None else "Enter para padrão"
    escolha_iface = input(
        f"\n[?] Digite o índice da interface [{texto_padrao}]: "
    ).strip()

    item_escolhido = None
    if escolha_iface.isdigit() and int(escolha_iface) < len(interfaces):
        item_escolhido = interfaces[int(escolha_iface)]
    elif not escolha_iface and indice_wifi_padrao is not None:
        item_escolhido = interfaces[indice_wifi_padrao]
    elif escolha_iface:
        item_escolhido = escolha_iface

    interface_selecionada = item_escolhido[0] if isinstance(item_escolhido, tuple) else item_escolhido

    try:
        qtd = int(input("[?] Quantidade máxima de pacotes HTTP/DNS [Padrão: 20]: ").strip() or "20")
        tempo = int(input("[?] Timeout máximo da captura em segundos [Padrão: 30]: ").strip() or "30")
    except ValueError:
        print("[!] Valores inválidos. Usando padrões (20 pacotes / 30s).")
        qtd, tempo = 20, 30

    print("\n" + "=" * 78)
    print(" CAPTURA E INSPEÇÃO DE TRÁFEGO DE APLICAÇÃO (HTTP / DNS)")
    print("=" * 78)
    iniciar_sniffer(interface=interface_selecionada, qtd_pacotes=qtd, timeout=tempo)
    print("=" * 78)


def main() -> None:
    print("=" * 78)
    print(" NETPROBE WI-FI - INVENTÁRIO DE REDE E INSPEÇÃO DE PACOTES (HTTP/DNS)")
    print("=" * 78)

    if not verificar_privilegios():
        print(
            "[!] AVISO: Privilégios de Administrador/Root não detectados.\n"
            "    Raw sockets (ICMP/ARP/Sniffing) podem falhar ou retornar resultados vazios.\n"
            "    Execute como Administrador (Windows) ou com 'sudo' (Linux/macOS).\n"
        )

    print("Selecione o modo de operação:")
    print("  [1] Inventário de Dispositivos e Portas (ICMP + ARP + TCP SYN)")
    print("  [2] Sniffer e Inspeção de Tráfego (HTTP porta 80 / DNS porta 53)")
    print("  [3] Execução Completa (Inventário seguido de Sniffer)")

    opcao = input("\n[?] Opção [Padrão: 1]: ").strip() or "1"

    if opcao == "1":
        executar_inventario()
    elif opcao == "2":
        executar_modulo_sniffer()
    elif opcao == "3":
        executar_inventario()
        executar_modulo_sniffer()
    else:
        print("[!] Opção inválida.")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Execução interrompida pelo usuário.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Erro fatal evitado. Causa: {e}")
        sys.exit(1)