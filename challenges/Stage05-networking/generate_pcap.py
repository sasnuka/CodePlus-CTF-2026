from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap

packets = []

CLIENT_MAC = "02:00:00:00:00:10"
SERVER_MAC = "02:00:00:00:00:20"


def tcp_stream(client_ip, server_ip, sport, request, response):

    client_seq = 1000
    server_seq = 5000
    dport = 8080

    # TCP handshake
    packets.append(
        Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
        IP(src=client_ip, dst=server_ip) /
        TCP(sport=sport, dport=dport, flags="S", seq=client_seq)
    )

    packets.append(
        Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
        IP(src=server_ip, dst=client_ip) /
        TCP(
            sport=dport,
            dport=sport,
            flags="SA",
            seq=server_seq,
            ack=client_seq + 1
        )
    )

    packets.append(
        Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
        IP(src=client_ip, dst=server_ip) /
        TCP(
            sport=sport,
            dport=dport,
            flags="A",
            seq=client_seq + 1,
            ack=server_seq + 1
        )
    )

    # HTTP request
    packets.append(
        Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
        IP(src=client_ip, dst=server_ip) /
        TCP(
            sport=sport,
            dport=dport,
            flags="PA",
            seq=client_seq + 1,
            ack=server_seq + 1
        ) /
        Raw(load=request)
    )

    # HTTP response
    packets.append(
        Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
        IP(src=server_ip, dst=client_ip) /
        TCP(
            sport=dport,
            dport=sport,
            flags="PA",
            seq=server_seq + 1,
            ack=client_seq + 1 + len(request)
        ) /
        Raw(load=response)
    )


# --------------------------------------------------
# Fake DNS traffic
# --------------------------------------------------

packets.append(
    Ether(
        src="02:00:00:00:00:30",
        dst="02:00:00:00:00:53"
    ) /
    IP(
        src="10.20.0.30",
        dst="10.20.0.53"
    ) /
    UDP(
        sport=53000,
        dport=53
    ) /
    DNS(
        id=100,
        rd=1,
        qd=DNSQR(qname="portal.codeplus.local")
    )
)


# --------------------------------------------------
# Normal fake HTTP traffic
# --------------------------------------------------

normal_request = (
    b"GET /status HTTP/1.1\r\n"
    b"Host: portal.codeplus.local\r\n"
    b"User-Agent: CodePlus-Browser/1.0\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

normal_response = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"CodePlus Campus Server\r\n"
    b"Status: Online\r\n"
    b"Security monitoring active\r\n"
)

tcp_stream(
    "10.20.0.10",
    "10.20.0.20",
    41000,
    normal_request,
    normal_response
)


# --------------------------------------------------
# Another normal fake connection
# --------------------------------------------------

health_request = (
    b"GET /health HTTP/1.1\r\n"
    b"Host: portal.codeplus.local\r\n"
    b"User-Agent: CodePlus-Monitor/1.0\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

health_response = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"Service healthy\r\n"
)

tcp_stream(
    "10.20.0.11",
    "10.20.0.20",
    42000,
    health_request,
    health_response
)


# --------------------------------------------------
# Suspicious CP-4821 traffic
# --------------------------------------------------

suspicious_request = (
    b"GET /internal/backend HTTP/1.1\r\n"
    b"Host: backend.codeplus.local\r\n"
    b"User-Agent: CodePlus-Agent/1.0\r\n"
    b"X-Session-ID: CP-4821\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

suspicious_response = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"X-Session-ID: CP-4821\r\n"
    b"X-CodePlus-Clue: CODEPLUS{traffic_stream_found}\r\n"
    b"X-Backend-User: campusops\r\n"
    b"X-Backend-Password: CP-4821\r\n"
    b"X-Next-Stage: SSH access is required for the final backend investigation.\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"Backend service response received.\r\n"
)


tcp_stream(
    "10.20.0.15",
    "10.20.0.25",
    48210,
    suspicious_request,
    suspicious_response
)


# --------------------------------------------------
# Save PCAP
# --------------------------------------------------

wrpcap("codeplus_traffic.pcap", packets)

print("Clean CodePlus Stage 05 PCAP created successfully.")
print("File: codeplus_traffic.pcap")
print("Session: CP-4821")
print("Flag: CODEPLUS{traffic_stream_found}")
print("Backend user: campusops")