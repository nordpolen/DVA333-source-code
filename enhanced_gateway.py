import socket
import struct
import threading
import time

# Configuration for control signal handling
UDP_IP = "12.1.1.131"
UDP_PORT = 6000
SERVER_IP = "192.168.3.3"
SERVER_PORT = 6001
SERVER_MAC = b"\x2c\xcf\x67\x80\x96\x07"
RAW_INTERFACE = "enp0s31f6.123"
GATEWAY_IP = "192.168.3.2"
GATEWAY_MAC = b"\x3c\x52\x82\x43\xb2\x29"

# Configuration for video stream handling
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 5000
CLIENT_IP = "12.1.1.134"
CLIENT_PORT = 5001
FRAGMENT_SIZE = 1024

# PCP to DSCP mapping (example)
PCP_TO_DSCP = {
    0: 0,
    1: 8,
    2: 16,
    3: 24,
    4: 32,
    5: 40, # Corresponds to PCP 5
    6: 48,
    7: 56
}

DSCP_TO_PCP = {
    0: 0,
    8: 1,
    16: 2,
    24: 3,
    32: 4,
    40: 5, # Corresponds to DSCP 40
    48: 6,
    56: 7
}
def extract_vlan_header(data):
    """ Extract PCP, VID, and Ethertype from VLAN header. """
    # The Ethertype field specifies the protocol encapsulated in the payload
    ethertype = struct.unpack('!H', data[12:14])[0] # Ethertype
    # The TCI field contains PCP (priority) and VID (identifier)
    tci = struct.unpack('!H', data[14:16])[0] # TCI
    pcp = (tci >> 13) & 0x07 # Extract PCP from TCI
    vid = tci & 0x0FFF # Extract VID from TCI
    print(f"Extracted VLAN header: PCP={pcp}, VID={vid}, Ethertype={hex(ethertype)}")
    return pcp, vid, ethertype

def find_jpeg_markers(data):
    """ Identify start and end markers for JPEG in the data. """
    # JPEG files have specific start (SOI) and end (EOI) markers
    start_marker = b'\xff\xd8'
    end_marker = b'\xff\xd9'

    start_index = data.find(start_marker)
    end_index = data.find(end_marker, start_index + 2) # Find the end marker after the start

    if start_index != -1 and end_index != -1:
        return start_index, end_index + 2 # Include the end marker
    return None, None

def extract_jpeg_frame(data):
    """ Extract a complete JPEG frame from the data. """
    # Locate JPEG start and end markers to extract a valid image
    start, end = find_jpeg_markers(data)
    if start is not None and end is not None:
        return data[start:end]
    return None

def save_frame_as_image(frame_buffer):
# Save the JPEG frame to a file with a timestamped name
    try:
        filename = f"received_frame_{int(time.time())}.jpg"
        with open(filename, "wb") as f:
            f.write(frame_buffer)
            print(f"Frame saved as {filename}, size: {len(frame_buffer)} bytes.")
    except Exception as e:
        print(f"Error saving image: {e}")

def add_ip_header(payload, src_ip, dst_ip, protocol=socket.IPPROTO_UDP):
    """ Create and prepend an IP header to the payload. """
    # IP header fields: version, IHL, TOS, total length, etc.
    version_ihl = 0x45
    tos = 0
    total_length = 20
    identification = 54321
    flags_fragment = 0
    ttl = 64
    header_checksum = 0
    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)

    ip_header = struct.pack(
    "!BBHHHBBH4s4s",
    version_ihl,
    tos,
    total_length,
    identification,
    flags_fragment,
    ttl,
    protocol,
    header_checksum,
    src_ip_bytes,
    dst_ip_bytes,
    )
    return ip_header + payload

def handle_steer_commands():
    """ Handle incoming steering commands over RAW UDP. """
    def tcp_handler():
        # Create a SOCK_RAW socket to capture and process packets
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        raw_sock.bind((UDP_IP, UDP_PORT))
        print(f"RAW UDP Server listening on {UDP_IP}:{UDP_PORT}")
        while True:
            try:
                packet, addr = raw_sock.recvfrom(65536)
                # Check if the packet is from the expected source
                if "12.1.1.134" in addr:
                    # Extract IP header and analyze ToS/DSCP
                    ip_header = packet[:20]
                    print(f"IP Header: {ip_header}")
                    tos = ip_header[1] # ToS is byte 1 in the IP header
                    dscp_value = (tos >> 2) & 0x3F # Extract DSCP value
                    print(f"Received packet from {addr}, DSCP value: {dscp_value}")
                    # Extract UDP header and payload for further processing
                    ip_header_length = (ip_header[0] & 0x0F) * 4
                    udp_header = packet[ip_header_length:ip_header_length + 8]

                    udp_payload = packet[ip_header_length + 8:]

                    # Decode payload to plaintext if possible
                    try:
                        payload_str = udp_payload.decode("utf-8").strip()
                        payload_with_newline = payload_str + "\n"
                        print(f"UDP Payload (decoded): {payload_with_newline}")
                        payload_with_newline = (payload_str + "\n").encode("utf-8")
                    except UnicodeDecodeError as e:
                        print(f"Error decoding payload: {e}")

                    # Debug: Output raw payload in hex format
                    print(f"UDP Payload (raw hex): {udp_payload[:50].hex()}")
                    # Map DSCP to PCP for VLAN tagging
                    pcp_value = DSCP_TO_PCP.get(dscp_value, 0)
                    print(f"Translated DSCP: {dscp_value} to PCP: {pcp_value}")
                    # Forward the packet with the appropriate PCP
                    translate_and_forward(payload_with_newline, pcp_value, dscp_value)
                else:
                    print("Ignoring irrelevant packets...")
            except Exception as e:
                print(f"Error in RAW UDP handler: {e}")

    def translate_and_forward(data, pcp_value, dscp_value):
        """Translate DSCP to PCP and forward the packet."""
        # Create a RAW socket for Ethernet frame construction
        steer_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        steer_sock.bind((RAW_INTERFACE, 0))

        # Prepare IP header and Ethernet frame for forwarding
        src_ip = GATEWAY_IP
        dst_ip = SERVER_IP
        data_with_ip_header = add_ip_header(data, src_ip, dst_ip)

        ethertype_vlan = b"\x81\x00"
        vlan_tci = (pcp_value & 0x07) << 13 | 123 # VLAN tagging with PCP and VID
        vlan_tag = struct.pack("!H", vlan_tci)
        ethertype_ip = b"\x08\x00"

        # Construct the Ethernet frame
        ethernet_frame = (
        SERVER_MAC +
        GATEWAY_MAC +
        ethertype_vlan +
        vlan_tag +
        ethertype_ip +
        data_with_ip_header
        )

        # Debug: Output Ethernet frame in hex format
        print(f"Ethernet Frame (hex): {ethernet_frame.hex()}")
        print(f"VLAN TCI: {hex(vlan_tci)}, PCP: {pcp_value}, VID: {123}")
        steer_sock.send(ethernet_frame)
        print(f"Forwarded packet to server with PCP {pcp_value} (from DSCP {dscp_value})")

    tcp_handler()

def handle_video_stream():
    """Handle incoming video stream packets."""
    recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    recv_sock.bind(("enp0s31f6", 0))
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("Gateway for video stream is active. Waiting for incoming packets...")
    while True:
        try:
            frame_buffer = b""

            while True:
                raw_data, addr = recv_sock.recvfrom(65536)
                # Extract VLAN header and validate Ethertype
                pcp, vid, ethertype = extract_vlan_header(raw_data)

                if ethertype != 0x8100:
                    print("Ignoring packet with unknown EtherType...")
                    continue

                # Calculate offsets for IP and UDP payloads
                ip_header_start = 14 + 4 # Ethernet (14) + VLAN (4)
                udp_payload_start = ip_header_start + 20 # IP header (20 bytes)
                udp_payload = raw_data[udp_payload_start:]

                print(f"UDP Payload (hex): {udp_payload[:50].hex()}")

                # Map PCP to DSCP for outgoing traffic
                dscp = PCP_TO_DSCP.get(pcp)
                tos_value = dscp << 2
                send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos_value)
                
                # Append UDP payload to frame buffer
                frame_buffer += udp_payload
                jpeg_frame = extract_jpeg_frame(frame_buffer)
                if jpeg_frame:
                    print(f"Received complete JPEG frame of {len(jpeg_frame)} bytes.")
                    break

            # Fragment and send the JPEG frame
            num_fragments = (len(frame_buffer) + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE
            timestamp = int(time.time() * 1000)

            for i in range(num_fragments):
                start = i * FRAGMENT_SIZE
                end = start + FRAGMENT_SIZE
                fragment = frame_buffer[start:end]
                header = f"{i}/{num_fragments}/{timestamp}".encode().ljust(20, b' ')
                send_data = header + fragment
                send_sock.sendto(send_data, (CLIENT_IP, CLIENT_PORT))
                # Debug: Optionally log fragment details
                # print(f"Sent fragment {i + 1}/{num_fragments}, size: {len(fragment)} bytes")
        except Exception as e:
            print(f"Error in video stream handling: {e}")

# Start the threads
threading.Thread(target=handle_steer_commands, daemon=True).start()
threading.Thread(target=handle_video_stream, daemon=True).start()

# Keep the main thread running
while True:
    time.sleep(1)
