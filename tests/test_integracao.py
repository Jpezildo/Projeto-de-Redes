import os
import sys
import tempfile
import unittest
from unittest.mock import patch

# Garante importação dos módulos da raiz do repositório
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scapy.all import (
    Ether,
    IP,
    IPv6,
    UDP,
    TCP,
    DNS,
    DNSQR,
    DNSRR,
    Raw,
    wrpcap,
)

from src.sniffer import extrair_cabecalhos, extrair_aplicacao, iniciar_sniffer
import src.netprobe as netprobe


class TestIntegracaoNetProbe(unittest.TestCase):
    """
    Issue #11: Testes de integração validando a extração de cabeçalhos (#09),
    decodificação segura de payload HTTP/DNS (#10) e fluxo de inventário.
    """

    def setUp(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            self.arquivo_pcap = tmp.name

        self.pacotes_teste = [
            # 1. Consulta DNS (UDP/53)
            Ether(src="aa:bb:cc:11:22:33", dst="ff:ee:dd:44:55:66")
            / IP(src="192.168.1.10", dst="8.8.8.8", ttl=64)
            / UDP(sport=54321, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="www.exemplo-redes.com.br")),

            # 2. Resposta DNS (UDP/53)
            Ether(src="ff:ee:dd:44:55:66", dst="aa:bb:cc:11:22:33")
            / IP(src="8.8.8.8", dst="192.168.1.10", ttl=57)
            / UDP(sport=53, dport=54321)
            / DNS(
                id=0,
                qr=1,
                aa=0,
                rd=1,
                ra=1,
                qd=DNSQR(qname="www.exemplo-redes.com.br"),
                an=DNSRR(rrname="www.exemplo-redes.com.br", type="A", rdata="93.184.216.34"),
            ),

            # 3. Requisição HTTP GET (TCP/80)
            Ether(src="aa:bb:cc:11:22:33", dst="ff:ee:dd:44:55:66")
            / IP(src="192.168.1.10", dst="93.184.216.34", ttl=64)
            / TCP(sport=51234, dport=80, flags="PA")
            / Raw(load=b"GET /api/status HTTP/1.1\r\nHost: exemplo-redes.com.br\r\nUser-Agent: NetProbe\r\n\r\n"),

            # 4. Resposta HTTP 200 OK (TCP/80)
            Ether(src="ff:ee:dd:44:55:66", dst="aa:bb:cc:11:22:33")
            / IP(src="93.184.216.34", dst="192.168.1.10", ttl=55)
            / TCP(sport=80, dport=51234, flags="PA")
            / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK"),

            # 5. Pacote TCP porta 80 sem payload (ACK puro)
            Ether()
            / IP(src="93.184.216.34", dst="192.168.1.10", ttl=55)
            / TCP(sport=80, dport=51234, flags="A"),

            # 6. Pacote TCP porta 80 com payload binário inválido para UTF-8
            Ether()
            / IP(src="192.168.1.10", dst="93.184.216.34", ttl=64)
            / TCP(sport=51235, dport=80, flags="PA")
            / Raw(load=b"\xff\xfe\x00\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"),

            # 7. Consulta DNS sobre IPv6
            Ether()
            / IPv6(src="2001:db8::1", dst="2001:4860:4860::8888", hlim=64)
            / UDP(sport=60000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="ipv6.teste.org")),
        ]

        wrpcap(self.arquivo_pcap, self.pacotes_teste)

    def tearDown(self):
        if hasattr(self, "arquivo_pcap") and os.path.exists(self.arquivo_pcap):
            os.remove(self.arquivo_pcap)

    def test_01_inspecao_cabecalhos_issue_09(self):
        """Valida extração de MAC, IPv4/IPv6, TTL, portas e flags TCP/UDP."""
        cab_http = extrair_cabecalhos(self.pacotes_teste[2])
        self.assertEqual(cab_http["mac_src"], "aa:bb:cc:11:22:33")
        self.assertEqual(cab_http["versao_ip"], "IPv4")
        self.assertEqual(cab_http["ip_src"], "192.168.1.10")
        self.assertEqual(cab_http["ip_dst"], "93.184.216.34")
        self.assertEqual(cab_http["ttl"], 64)
        self.assertEqual(cab_http["protocolo"], "TCP")
        self.assertEqual(cab_http["sport"], 51234)
        self.assertEqual(cab_http["dport"], 80)
        self.assertEqual(cab_http["flags"], "PA")

        cab_ipv6 = extrair_cabecalhos(self.pacotes_teste[6])
        self.assertEqual(cab_ipv6["versao_ip"], "IPv6")
        self.assertEqual(cab_ipv6["ttl"], 64)
        self.assertEqual(cab_ipv6["protocolo"], "UDP")

    def test_02_inspecao_aplicacao_issue_10(self):
        """Valida decodificação HTTP/DNS e resiliência contra pacotes vazios/binários."""
        # DNS Query
        app_dns_q = extrair_aplicacao(self.pacotes_teste[0])
        self.assertEqual(app_dns_q["servico"], "DNS Query")
        self.assertIn("www.exemplo-redes.com.br", app_dns_q["detalhe"])

        # DNS Response
        app_dns_r = extrair_aplicacao(self.pacotes_teste[1])
        self.assertEqual(app_dns_r["servico"], "DNS Response")
        self.assertIn("93.184.216.34", app_dns_r["detalhe"])

        # HTTP GET
        app_http_req = extrair_aplicacao(self.pacotes_teste[2])
        self.assertEqual(app_http_req["servico"], "HTTP Request")
        self.assertIn("GET /api/status HTTP/1.1", app_http_req["detalhe"])
        self.assertIn("exemplo-redes.com.br", app_http_req["detalhe"])

        # HTTP 200 OK
        app_http_res = extrair_aplicacao(self.pacotes_teste[3])
        self.assertEqual(app_http_res["servico"], "HTTP Response")
        self.assertIn("HTTP/1.1 200 OK", app_http_res["detalhe"])

        # TCP Vazio
        app_vazio = extrair_aplicacao(self.pacotes_teste[4])
        self.assertIn("sem carga útil", app_vazio["detalhe"])

        # Binário não-UTF8
        app_binario = extrair_aplicacao(self.pacotes_teste[5])
        self.assertIn("binária", app_binario["detalhe"])

    def test_03_pipeline_sniffer_pcap(self):
        """Valida leitura completa via iniciar_sniffer em modo offline (.pcap)."""
        resultados = iniciar_sniffer(arquivo_pcap=self.arquivo_pcap)
        self.assertEqual(len(resultados), 7)

    @patch("netprobe.consultar_cache_arp_so", return_value=None)
    @patch("netprobe.varredura_porta_syn")
    @patch("netprobe.varredura_arp_lote")
    @patch("netprobe.varredura_icmp")
    def test_04_fluxo_inventario_netprobe(self, mock_icmp, mock_arp, mock_syn, _mock_cache):
        """Valida integração do inventário: ICMP ativo + contorno ARP + varredura de portas."""
        mock_icmp.side_effect = lambda ip, timeout: ip if ip == "192.168.1.1" else None
        mock_arp.return_value = {
            "192.168.1.1": "00:11:22:33:44:55",
            "192.168.1.2": "aa:bb:cc:dd:ee:ff",
        }
        mock_syn.side_effect = lambda ip, porta, timeout: porta if (ip == "192.168.1.1" and porta == 80) else None

        entradas = iter(["192.168.1.0/30", "0.1", "80", "81", "s"])
        with patch("builtins.input", lambda _: next(entradas)):
            netprobe.executar_inventario()

        self.assertTrue(mock_arp.called)
        self.assertTrue(mock_syn.called)


if __name__ == "__main__":
    unittest.main()