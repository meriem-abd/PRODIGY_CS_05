from scapy.all import sniff, IP, TCP, UDP, Raw

# This function is called for each captured packet
def callback_function(packet):
    # Check if the packet contains an IP layer
    if IP in packet:
        # Extract the IP layer from the packet
        ip_layer = packet[IP]
        # Get the source and destination IP addresses
        source = ip_layer.src
        destination = ip_layer.dst
        # Check if the packet has a Raw layer (payload)
        payload = str(packet[Raw].load) if Raw in packet else "no payload"
        # Print the source and destination IP addresses along with the payload
        print(f"IP address's source: {source}\tIP address's destination: {destination}\tpayload: {payload}\t")
    
    # Initialize the protocol variable
    protocol = None
    # Determine if the packet uses TCP or UDP
    if TCP in packet:
        protocol = 'TCP'
    elif UDP in packet:
        protocol = 'UDP'
    
    # Print the protocol used by the packet
    print(f"protocol: {protocol}")

# Start sniffing packets
# prn specifies the callback function, count limits the number of packets to capture, 
# filter specifies to capture only IP packets, and store=0 prevents storing the packets in memory
sniff(prn=callback_function, count=10, filter="ip", store=0)

