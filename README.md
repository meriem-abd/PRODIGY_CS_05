<h1>Network Packet Sniffer:</h1>
<p>This script is a simple packet sniffer implemented in Python using the Scapy library. Its primary function is to capture IP packets from the network and extract key information such as source and destination IP addresses, the payload, and the transport layer protocol (TCP or UDP).</p>

<h2>IP layer manipulation:</h2>
<p>When a packet is captured, the script first checks if it contains an IP layer. If it does, it retrieves the source and destination IP addresses from the packet. It also checks for any payload data within the packet. If the payload is present, it is converted to a string; if not, the script notes that there is "no payload." This information is then printed to the console, providing a clear view of the packet's contents.</p>
<h2>protocol type:</h2>
<p>In addition to IP information, the script determines the type of transport layer protocol used by the packet. It identifies whether the packet is using TCP or UDP and prints this information as well.</p>
<h2>sniffing process:</h2>
The sniffing process is initiated with specific parameters: the script captures a limited number of packets (10 in this case), filters to only include IP packets, and avoids storing packets in memory to conserve resources.
<h2>warning:</h2>
<p>this packet sniffer serves as a valuable tool for basic network analysis and monitoring, making it easier to troubleshoot network issues and understand traffic flow. it is used for educational purposes only, ensure that you have permission to monitor network traffic on any network you are analyzing. Unauthorized packet sniffing may violate privacy laws and network policies.</p>
