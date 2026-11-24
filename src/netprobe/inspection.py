def extract_headers(packet):
    headers = {}

    ethernet = packet.getlayer(Ether)

    if ethernet:
        headers["ethernet_src"] = ethernet.src
        headers["ethernet_dst"] = ethernet.dst
        headers["ethertype"] = hex(int(ethernet.type))

    ipv4 = packet.getlayer(IP)
    ipv6 = packet.getlayer(IPv6)

    if ipv4:
        headers.update({
            "ip_version": 4,
            "src_ip": ipv4.src,
            "dst_ip": ipv4.dst,
            "ttl": int(ipv4.ttl),
            "ip_flags": str(ipv4.flags)
        })

    elif ipv6:
        headers.update({
            "ip_version": 6,
            "src_ip": ipv6.src,
            "dst_ip": ipv6.dst,
            "hop_limit": int(ipv6.hlim)
        })

    tcp = packet.getlayer(TCP)
    udp = packet.getlayer(UDP)

    if tcp:
        headers.update({
            "transport": "TCP",
            "src_port": int(tcp.sport),
            "dst_port": int(tcp.dport),
            "tcp_flags": str(tcp.flags)
        })

    elif udp:
        headers.update({
            "transport": "UDP",
            "src_port": int(udp.sport),
            "dst_port": int(udp.dport)
        })

    return headers