from scapy.all import sniff, IP, TCP, UDP, Raw

def callback_function(packet):
    if IP in packet:
        ip_layer=packet[IP]
        source=ip_layer.src
        destination=ip_layer.dst
        payload= str(packet[Raw].load) if Raw in packet else "no payload"
        print(f"IP address's source: {source}\tIP address's destination:{destination}\tpayload: {payload}\t")
    protocol = None
    if TCP in packet:
        protocol='TCP'
    elif UDP in packet:
        protocol='UDP'
    print(f"protocol: {protocol}")

sniff(prn=callback_function , count=10 , filter="ip" , store=0)

