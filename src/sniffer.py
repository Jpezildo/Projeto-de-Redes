import logging
from scapy.all import (
    sniff,
    wrpcap,
    conf,
    get_if_list,
    Ether,
    IP,
    IPv6,
    TCP,
    UDP,
    DNS,
    DNSQR,
    DNSRR,
    Raw,
)

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

METODOS_HTTP = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE")

DNS_TIPOS = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
}

DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def listar_interfaces() -> list[tuple[str, str]]:
    """Retorna lista de (identificador_scapy, descricao_legivel) das interfaces."""
    resultado = []
    try:
        for iface in conf.ifaces.values():
            nome_legivel = getattr(iface, "name", "") or getattr(iface, "description", "")
            ip_iface = getattr(iface, "ip", "") or "Sem IP"
            guid = getattr(iface, "network_name", None) or nome_legivel
            if guid:
                resultado.append((guid, f"{nome_legivel} (IP: {ip_iface})"))
    except Exception:
        for g in get_if_list():
            resultado.append((g, g))
    return resultado


def filtro_http_dns(pacote) -> bool:
    """Filtro L4 para isolar tráfego HTTP (TCP/80) e DNS (UDP/53)."""
    if pacote.haslayer(TCP) and (pacote[TCP].sport == 80 or pacote[TCP].dport == 80):
        return True
    if pacote.haslayer(UDP) and (pacote[UDP].sport == 53 or pacote[UDP].dport == 53):
        return True
    return False


def extrair_cabecalhos(pacote) -> dict:
    """
    Issue #09: Extrai campos das camadas L2 (Ethernet), L3 (IPv4/IPv6 com TTL vs Hop Limit)
    e L4 (TCP/UDP com portas de origem/destino e flags).
    """
    info = {
        "mac_src": pacote[Ether].src if pacote.haslayer(Ether) else "N/A",
        "mac_dst": pacote[Ether].dst if pacote.haslayer(Ether) else "N/A",
        "versao_ip": None,
        "ip_src": None,
        "ip_dst": None,
        "campo_vida_nome": "TTL",
        "campo_vida_valor": None,
        "protocolo": "OUTRO",
        "sport": None,
        "dport": None,
        "flags": None,
        "seq": None,
    }

    if pacote.haslayer(IP):
        info["versao_ip"] = "IPv4"
        info["ip_src"] = pacote[IP].src
        info["ip_dst"] = pacote[IP].dst
        info["campo_vida_nome"] = "TTL"
        info["campo_vida_valor"] = pacote[IP].ttl
    elif pacote.haslayer(IPv6):
        info["versao_ip"] = "IPv6"
        info["ip_src"] = pacote[IPv6].src
        info["ip_dst"] = pacote[IPv6].dst
        info["campo_vida_nome"] = "Hop Limit"
        info["campo_vida_valor"] = pacote[IPv6].hlim

    if pacote.haslayer(TCP):
        info["protocolo"] = "TCP"
        info["sport"] = pacote[TCP].sport
        info["dport"] = pacote[TCP].dport
        info["flags"] = str(pacote[TCP].flags)
        info["seq"] = pacote[TCP].seq
    elif pacote.haslayer(UDP):
        info["protocolo"] = "UDP"
        info["sport"] = pacote[UDP].sport
        info["dport"] = pacote[UDP].dport

    return info


def _decodificar_dns(pacote) -> dict:
    """Extrai Transaction ID, Domínio, Tipo, RCODE e registros de resposta DNS."""
    dns = pacote[DNS]
    tx_id = dns.id
    rcode_str = DNS_RCODES.get(dns.rcode, f"RCODE({dns.rcode})")

    dominio = "N/A"
    tipo_str = "A"
    if pacote.haslayer(DNSQR):
        qname = pacote[DNSQR].qname
        dominio = (
            qname.decode("utf-8", errors="replace").rstrip(".")
            if isinstance(qname, bytes)
            else str(qname).rstrip(".")
        )
        tipo_str = DNS_TIPOS.get(pacote[DNSQR].qtype, str(pacote[DNSQR].qtype))

    if dns.qr == 0:
        detalhe = (
            f"Domínio: {dominio} | Tipo: {tipo_str} | Transaction ID: {tx_id}"
        )
        return {"servico": "DNS Query", "detalhe": detalhe}

    respostas = []
    atual = dns.an
    while atual and isinstance(atual, DNSRR):
        dado = atual.rdata
        if isinstance(dado, bytes):
            dado = dado.decode("utf-8", errors="replace").rstrip(".")
        tipo_rr = DNS_TIPOS.get(atual.type, str(atual.type))
        respostas.append(f"{dado} ({tipo_rr})")
        atual = atual.payload if isinstance(atual.payload, DNSRR) else None

    if respostas:
        lista_resp = ", ".join(respostas)
        detalhe = (
            f"Domínio: {dominio} | Tipo: {tipo_str} | Transaction ID: {tx_id} | "
            f"Código: {rcode_str} | Respostas: {lista_resp}"
        )
    else:
        detalhe = (
            f"Domínio: {dominio} | Tipo: {tipo_str} | Transaction ID: {tx_id} | "
            f"Código: {rcode_str} | Respostas: Nenhum registro {tipo_str} retornado"
        )

    return {"servico": "DNS Response", "detalhe": detalhe}


def _analisar_payload_http(payload_bruto: bytes) -> dict:
    """Interpreta uma mensagem HTTP completa (após reconstrução do fluxo TCP)."""
    bytes_imprimiveis = sum(32 <= b <= 126 or b in (9, 10, 13) for b in payload_bruto)
    if len(payload_bruto) > 0 and (bytes_imprimiveis / len(payload_bruto)) < 0.7:
        return {
            "servico": "HTTP/Binário",
            "detalhe": f"Carga útil binária ou comprimida ({len(payload_bruto)} bytes)",
        }

    texto = payload_bruto.decode("utf-8", errors="replace")
    partes = texto.split("\r\n\r\n", 1)
    bloco_cabecalho = partes[0]
    corpo = partes[1] if len(partes) > 1 else ""

    linhas = bloco_cabecalho.splitlines()
    primeira_linha = linhas[0].strip() if linhas else ""

    host = next(
        (l.split(":", 1)[1].strip() for l in linhas[1:] if l.lower().startswith("host:")),
        "",
    )
    sufixo_host = f" | Host: {host}" if host else ""
    resumo_corpo = ""
    if corpo.strip():
        preview = corpo.strip().replace("\r\n", " ").replace("\n", " ")[:80]
        resumo_corpo = f" | Body: {preview}"

    if any(primeira_linha.startswith(metodo + " ") for metodo in METODOS_HTTP):
        return {
            "servico": "HTTP Request",
            "detalhe": f"HTTP {primeira_linha}{sufixo_host}{resumo_corpo}",
        }
    if primeira_linha.startswith("HTTP/"):
        return {
            "servico": "HTTP Response",
            "detalhe": f"{primeira_linha}{resumo_corpo}",
        }

    return {
        "servico": "HTTP Dados",
        "detalhe": f"Payload HTTP ({len(payload_bruto)} bytes){resumo_corpo}",
    }


def extrair_aplicacao(pacote) -> dict:
    """Decodifica a camada de aplicação para um pacote isolado."""
    if pacote.haslayer(DNS):
        return _decodificar_dns(pacote)

    if pacote.haslayer(TCP) and (pacote[TCP].sport == 80 or pacote[TCP].dport == 80):
        if not pacote.haslayer(Raw) or not pacote[Raw].load:
            return {
                "servico": "HTTP (Controle TCP)",
                "detalhe": "Pacote sem carga útil (Handshake/ACK/FIN)",
            }
        return _analisar_payload_http(pacote[Raw].load)

    return {"servico": "DESCONHECIDO", "detalhe": "Sem payload de aplicação"}


class ReconstrutorFluxoTCP:
    """
    Issue #10: Reconstrói segmentos TCP fora de ordem ou fragmentados por fluxo
    (ip_src, sport, ip_dst, dport) utilizando o número de sequência (SEQ).
    """

    def __init__(self):
        # chave -> {"segmentos": {seq: bytes}}
        self.fluxos: dict[tuple, dict] = {}

    def _montar_continuo(self, segmentos: dict[int, bytes]) -> bytes:
        if not segmentos:
            return b""
        seqs_ordenadas = sorted(segmentos.keys())
        buffer = bytearray()
        seq_esperado = None

        for seq in seqs_ordenadas:
            dados = segmentos[seq]
            if seq_esperado is None:
                buffer.extend(dados)
                seq_esperado = seq + len(dados)
            elif seq == seq_esperado:
                buffer.extend(dados)
                seq_esperado += len(dados)
            elif seq < seq_esperado:
                # Sobreposição ou retransmissão parcial
                offset = seq_esperado - seq
                if offset < len(dados):
                    buffer.extend(dados[offset:])
                    seq_esperado += len(dados) - offset
            else:
                # Lacuna: aguarda segmento faltante
                break

        return bytes(buffer)

    def _mensagem_http_completa(self, dados: bytes) -> tuple[bool, int]:
        """Verifica se o buffer possui cabeçalho HTTP completo e todo o Content-Length."""
        fim_cab = dados.find(b"\r\n\r\n")
        if fim_cab == -1:
            return False, 0

        cab_texto = dados[:fim_cab].decode("utf-8", errors="replace")
        content_length = 0
        for linha in cab_texto.splitlines()[1:]:
            if linha.lower().startswith("content-length:"):
                try:
                    content_length = int(linha.split(":", 1)[1].strip())
                except ValueError:
                    content_length = 0
                break

        tamanho_total = fim_cab + 4 + content_length
        if len(dados) >= tamanho_total:
            return True, tamanho_total
        return False, 0

    def processar(self, cab: dict, payload: bytes, flags: str) -> bytes | None:
        chave = (cab["ip_src"], cab["sport"], cab["ip_dst"], cab["dport"])
        fluxo = self.fluxos.setdefault(chave, {"segmentos": {}})

        if payload and cab["seq"] is not None:
            fluxo["segmentos"][cab["seq"]] = payload

        montado = self._montar_continuo(fluxo["segmentos"])
        if not montado:
            return None

        completa, tamanho = self._mensagem_http_completa(montado)
        if completa:
            mensagem = montado[:tamanho]
            fluxo["segmentos"].clear()
            return mensagem

        # Se a conexão encerrar (FIN ou RST), libera o que foi acumulado
        if any(f in flags for f in ("F", "R")):
            fluxo["segmentos"].clear()
            return montado

        return None


def formatar_resumo_pacote(cab: dict, app: dict, indice: int = 1) -> str:
    """Formata a exibição estruturada por camadas (L2, L3, L4 e L7)."""
    porta_src = cab["sport"] if cab["sport"] is not None else "N/A"
    porta_dst = cab["dport"] if cab["dport"] is not None else "N/A"
    flags_str = f" | Flags: {cab['flags']}" if cab["flags"] else ""
    campo_vida = f"{cab['campo_vida_nome']} = {cab['campo_vida_valor']}"

    linhas = [
        f"[Evento #{indice:02d}] {cab['protocolo']} ({cab['versao_ip']}) — {app['servico']}",
        f"  ├─ Camada 2 (Enlace)    : MAC Origem: {cab['mac_src']}  ->  MAC Destino: {cab['mac_dst']}",
        f"  ├─ Camada 3 (Rede)      : IP Origem : {cab['ip_src']}  ->  IP Destino : {cab['ip_dst']} | {campo_vida}",
        f"  ├─ Camada 4 (Transporte): Porta Orig: {porta_src}  ->  Porta Dest : {porta_dst}{flags_str}",
        f"  └─ Camada 7 (Aplicação) : {app['detalhe']}",
        "-" * 78,
    ]
    return "\n".join(linhas)


def iniciar_sniffer(
    interface: str | tuple | None = None,
    qtd_pacotes: int = 20,
    timeout: int = 30,
    arquivo_pcap: str | None = None,
    salvar_evidencia: str = "captura_netprobe.pcap",
) -> list[dict]:
    """
    Executa captura ao vivo (ou leitura offline de .pcap) filtrando
    tráfego HTTP (TCP 80) com reconstrução de fluxo e consultas DNS (UDP 53).
    """
    if isinstance(interface, tuple):
        interface = interface[0]

    capturados = []
    pacotes_brutos = []
    reconstrutor = ReconstrutorFluxoTCP()

    def _callback(pacote):
        cab = extrair_cabecalhos(pacote)
        if not cab["ip_src"]:
            return

        pacotes_brutos.append(pacote)

        # Caso 1: DNS (UDP/53)
        if pacote.haslayer(DNS):
            app = _decodificar_dns(pacote)
            capturados.append({"cabecalhos": cab, "aplicacao": app})
            print(formatar_resumo_pacote(cab, app, indice=len(capturados)))
            return

        # Caso 2: HTTP (TCP/80) com TCP Stream Reassembly
        if pacote.haslayer(TCP) and (pacote[TCP].sport == 80 or pacote[TCP].dport == 80):
            payload = bytes(pacote[Raw].load) if pacote.haslayer(Raw) else b""
            flags = cab["flags"] or ""

            if not payload:
                app = {
                    "servico": "HTTP (Controle TCP)",
                    "detalhe": "Pacote sem carga útil (Handshake/ACK/FIN)",
                }
                capturados.append({"cabecalhos": cab, "aplicacao": app})
                print(formatar_resumo_pacote(cab, app, indice=len(capturados)))
                return

            stream_completo = reconstrutor.processar(cab, payload, flags)
            if stream_completo is not None:
                app = _analisar_payload_http(stream_completo)
                capturados.append({"cabecalhos": cab, "aplicacao": app})
                print(formatar_resumo_pacote(cab, app, indice=len(capturados)))

    if arquivo_pcap:
        print(f"[*] Lendo pacotes do arquivo '{arquivo_pcap}' (filtro HTTP/DNS)...")
        sniff(offline=arquivo_pcap, lfilter=filtro_http_dns, prn=_callback, store=False)
    else:
        alvo_iface = interface if interface else "Padrão do Sistema"
        print(
            f"[*] Capturando tráfego na interface [{alvo_iface}] "
            f"(Filtro: HTTP TCP/80 e DNS UDP/53 | Máx: {qtd_pacotes} pacotes | Timeout: {timeout}s)..."
        )
        print("[*] Dica: Execute o cliente de laboratório (demo.lab) para gerar DNS, GET e POST.\n")
        print("-" * 78)
        sniff(
            iface=interface,
            lfilter=filtro_http_dns,
            prn=_callback,
            count=qtd_pacotes,
            timeout=timeout,
            store=False,
            promisc=True,
        )

        if pacotes_brutos and salvar_evidencia:
            try:
                wrpcap(salvar_evidencia, pacotes_brutos)
                print(f"\n[*] Evidência PCAP salva em: {salvar_evidencia} ({len(pacotes_brutos)} quadros)")
            except Exception as e:
                print(f"\n[!] Aviso ao salvar PCAP: {e}")

    print(f"[*] Captura finalizada. Total de eventos HTTP/DNS exibidos: {len(capturados)}")
    return capturados