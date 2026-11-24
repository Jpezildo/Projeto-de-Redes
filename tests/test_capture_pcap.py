from scapy.all import (
    Ether, IP, TCP, UDP,
    DNS, DNSQR, Raw, wrpcap
)

pacotes = [
    Ether() / IP(
        src="192.0.2.10",
        dst="192.0.2.20"
    ) / TCP(
        sport=51515,
        dport=80,
        flags="PA"
    ) / Raw(
        load=b"GET / HTTP/1.1\r\nHost: demo.lab\r\n\r\n"
    ),

    Ether() / IP(
        src="192.0.2.10",
        dst="192.0.2.20"
    ) / UDP(
        sport=53000,
        dport=53
    ) / DNS(
        rd=1,
        qd=DNSQR(qname="demo.lab")
    )
]

wrpcap("teste.pcap", pacotes)