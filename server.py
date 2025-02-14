import threading
import socket
import cv2
import struct
import subprocess
from time import perf_counter

# Configuration for video feed
SERVER_IP = "192.168.3.3" # Server IP address
SERVER_MAC = b"\x2c\xcf\x67\x80\x96\x07" # Server MAC address
MIDDLEMAN_IP = "192.168.3.2" # Middleman/Gateway IP address
MIDDLEMAN_MAC = b"\x3c\x52\x82\x43\xb2\x29" # Middleman/Gateway MAC address
MIDDLEMAN_PORT = 5000 # Port for communication with Middleman/Gateway

MAX_PACKET_SIZE = 1400 # Maximum size for data packets in bytes
FRAME_QUALITY = 10 # JPEG frame quality
FPS = 10 # Frames per second
RESOLUTION = (320, 240) # Camera resolution (width, height)
PCP_VALUE = 5 # Priority Code Point for VLAN tagging

# GPIO and PWM configurations for car steering
BUFFER_SIZE = 65535 # Buffer size for receiving data
TCP_IP = "0.0.0.0" # TCP server IP address
TCP_PORT = 6001 # TCP server port

pins = {
    'IN1': 17,
    'IN2': 18,
    'IN3': 22,
    'IN4': 23,
}

pwm_ena_path = "/sys/class/pwm/pwmchip0/pwm0/" # Path to PWM channel 0
pwm_enb_path = "/sys/class/pwm/pwmchip0/pwm1/" # Path to PWM channel 1

def create_raw_socket():
    """
    Creates a raw socket bound to a specific network interface.
    Returns:
    socket: A raw socket object.
    Raises:
    PermissionError: If the script lacks the required privileges.
    """
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind(("eth0.123", 0)) # Replace "eth0.123" with your interface
        return sock
    except PermissionError:
        print("Root privilege needed to use raw sockets.")
        exit()
def create_ethernet_header(dest_mac, src_mac, ethertype):
    """
    Creates an Ethernet header for the packet.
    Args:
        dest_mac (str): Destination MAC address.
        src_mac (str): Source MAC address.
        ethertype (int): Ethertype (e.g., 0x8100 for VLAN).
    Returns:
        bytes: Ethernet header formatted as bytes.
    """
    return struct.pack('!6s6sH', bytes.fromhex(dest_mac), bytes.fromhex(src_mac), ethertype)

def create_vlan_header(pcp, vid):
    """
    Creates a VLAN header.
    Args:
        pcp (int): Priority Code Point.
        vid (int): VLAN ID.
    Returns:
        tuple: VLAN tag, TCI, and VID values for the header.
    """
    tci = (pcp & 0x07) << 13 | 123
    vlan_tag = struct.pack('!H', tci)
    return vlan_tag, tci, vid

def add_ip_header(payload, src_ip, dst_ip, protocol=socket.IPPROTO_UDP):
    version_ihl = 0x45 # IPv4 and header length
    tos = 0 # Type of Service
    total_length = 20 + len(payload) # IP header length + payload
    identification = 54321 # Unique identifier for fragments
    flags_fragment = 0 # Flags and fragment offset
    ttl = 64 # Time to Live
    header_checksum = 0 # Placeholder for checksum
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

# Function for handling camera feed
def camera_feed():
    """
    Captures video frames from the camera and sends them via raw socket to the Gateway.
    Each frame is encoded as JPEG and split into packets if necessary.
    """
    gst_pipeline = (
        f"libcamerasrc ! "
        f"video/x-raw,format=YUY2,width={RESOLUTION[0]},height={RESOLUTION[1]}, fps={FPS} ! "
        f"videoconvert ! "
        f"appsink"
    )

    cap = cv2.VideoCapture(gst_pipeline, cv2.CAP_GSTREAMER)
    if not cap.isOpened():
        print("Could not open camera...")
        return
    
    sock = create_raw_socket()

    dest_mac = "3c:52:82:43:b2:29" # Gateway MAC address
    src_mac = "2c:cf:67:80:96:07" # Server MAC address
    dest_mac = dest_mac.replace(":", "").lower()
    src_mac = src_mac.replace(":", "").lower()

    try:
        while True:
            # Capture a frame from the camera
            ret, frame = cap.read()
            if not ret:
                print("Could not read from camera...")
                break

            # Encode the frame as JPEG and calculate its size
            _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, FRAME_QUALITY])
            frame_data = buffer.tobytes()
            total_size = len(frame_data)
            
            # Split the frame into smaller packets if needed
            segment_count = (total_size // MAX_PACKET_SIZE) + 1
            
            for i in range(segment_count):
                start = i * MAX_PACKET_SIZE
                end = start + MAX_PACKET_SIZE
                payload = frame_data[start:end]

                # Add IP header to the payload
                ip_udp_payload = payload
                src_ip = SERVER_IP
                dst_ip = MIDDLEMAN_IP
                data_with_ip_header = add_ip_header(ip_udp_payload, src_ip, dst_ip)

                # Create the Ethernet frame
                ethertype_vlan = b"\x81\x00"
                vlan_tci = (PCP_VALUE & 0x07) << 13 | 123
                vlan_tag = struct.pack("!H", (PCP_VALUE & 0x07) << 13 | 123)
                ethertype_ip = b"\x08\x00"
                MIDDLEMAN_MAC = bytes.fromhex("3c528243b229")
                SERVER_MAC = bytes.fromhex("2ccf67809607")
                ethernet_frame = (
                    MIDDLEMAN_MAC +
                    SERVER_MAC +
                    ethertype_vlan +
                    vlan_tag +
                    ethertype_ip +
                    data_with_ip_header
                )

                # Send the frame
                sock.send(ethernet_frame)
    except KeyboardInterrupt:
        print("Stopping camera feed...")
    finally:
        cap.release()
        sock.close()

# Function for handling steering commands
def car_steering():
    """
    Listens for VLAN-tagged packets and processes steering commands to control the car.
    Commands include directional movement and PWM duty cycle adjustments.
    """
    raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    raw_sock.bind(("eth0", 0))

    print(f"Listening for VLAN-tagged packets on eth0...")
    buffer = ""

    def set_pwm(pwm_path, duty_cycle, frequency=1000):
        """
        Configures a PWM channel with the specified duty cycle and frequency.
        Args:
        pwm_path (str): Path to the PWM channel.
        duty_cycle (int): Duty cycle percentage (0-100).
        frequency (int): PWM frequency in Hz.
        """
        if duty_cycle < 0 or duty_cycle > 100:
            print(f"Invalid duty_cycle value: {duty_cycle}")
            return
        period_ns = int(1e9 / frequency)
        duty_cycle_ns = int(period_ns * (duty_cycle / 100))
        try:
            with open(pwm_path + "period", "w") as f:
                f.write(f"{period_ns}")
            with open(pwm_path + "duty_cycle", "w") as f:
                f.write(f"{duty_cycle_ns}")
            with open(pwm_path + "enable", "w") as f:
                f.write("1")
        except Exception as e:
            print(f"Error setting PWM: {e}")

        def stop():
            for pin in pins.values():
                set_gpio(pin, 0)
            stop_pwm(pwm_ena_path)
            stop_pwm(pwm_enb_path)
            print("Stopped")

        def stop_pwm(pwm_path):
            try:
                with open(pwm_path + "enable", "w") as f:
                    f.write("0")
            except OSError as e:
                print(f"Failed to disable PWM at {pwm_path}: {e}")

        def set_gpio(pin, value):
            subprocess.run(["gpioset", "gpiochip0", f"{pin}={value}"])

        def advance_with_turn(left_duty_cycle, right_duty_cycle):
            set_gpio(pins['IN1'], 1)
            set_gpio(pins['IN2'], 0)
            set_gpio(pins['IN3'], 1)
            set_gpio(pins['IN4'], 0)
            set_pwm(pwm_ena_path, left_duty_cycle)
            set_pwm(pwm_enb_path, right_duty_cycle)
            print("Advancing...")

        def reverse_with_turn(left_duty_cycle, right_duty_cycle):
            set_gpio(pins['IN1'], 0)
            set_gpio(pins['IN2'], 1)
            set_gpio(pins['IN3'], 0)
            set_gpio(pins['IN4'], 1)
            set_pwm(pwm_ena_path, left_duty_cycle)
            set_pwm(pwm_enb_path, right_duty_cycle)
            print("Reversing...")

        def turn_right(left_duty_cycle, right_duty_cycle):
            set_gpio(pins['IN1'], 1)
            set_gpio(pins['IN2'], 0)
            set_gpio(pins['IN3'], 0)
            set_gpio(pins['IN4'], 1)
            set_pwm(pwm_ena_path, left_duty_cycle)
            set_pwm(pwm_enb_path, right_duty_cycle)
            print("Turning right...")

        def turn_left(left_duty_cycle, right_duty_cycle):
            set_gpio(pins['IN1'], 0)
            set_gpio(pins['IN2'], 1)
            set_gpio(pins['IN3'], 1)
            set_gpio(pins['IN4'], 0)
            set_pwm(pwm_ena_path, left_duty_cycle)
            set_pwm(pwm_enb_path, right_duty_cycle)
            print("Turning left...")

        def process_message(msg):
            """
            Processes steering commands received from the network.
            Args:
            msg (str): Command message in the format "<timestamp>,<left_duty_cycle>,
            <right_duty_cycle>,<direction>".
            """
            try:
                print(f"Processing message: {msg}")
                parts = msg.split(",")
                if len(parts) != 4:
                    raise ValueError(f"Incorrect message format: {msg}")
                
                left_duty_cycle = int(parts[1])
                right_duty_cycle = int(parts[2])
                direction = int(parts[3])

                # Actions based on direction
                if direction == 0:
                    stop()
                elif direction == 1:
                    advance_with_turn(left_duty_cycle, right_duty_cycle)
                elif direction == -1:
                    reverse_with_turn(left_duty_cycle, right_duty_cycle)
                elif direction == 2:
                    turn_right(left_duty_cycle, right_duty_cycle)
                elif direction == -2:
                    turn_left(left_duty_cycle, right_duty_cycle)
                else:
                    print(f"Unknown direction: {direction}")
            except ValueError as ve:
                print(f"Error in process_message: {ve}")
            except Exception as e:
                print(f"Unexpected error in process_message: {e}")

        try:
            while True:
                # Receive a packet from the raw socket
                packet, addr = raw_sock.recvfrom(65536)
                print("Received packet from Gateway...")

                # Extract Ethernet header (14 bytes)
                eth_header = packet[:14]
                dest_mac, src_mac, ethertype = struct.unpack("!6s6sH", eth_header)
                print("Ethernet Header Analysis:")
                print(f" Destination MAC: {dest_mac.hex()} (bytes: {dest_mac})")
                print(f" Source MAC: {src_mac.hex()} (bytes: {src_mac})")
                print(f" Ethertype: {hex(ethertype)}")

                # Check if the packet is VLAN-tagged
                if ethertype == 0x8100 or ethertype == 0x0800:
                    print("Identified VLAN packet!" if ethertype == 0x8100 else "Identified IPv4 packet!")
                    if ethertype == 0x8100: # VLAN-tagged packet
                        vlan_header = packet[14:18]
                        vlan_fields = struct.unpack("!HH", vlan_header)
                        vlan_tci = vlan_fields[0]
                        pcp = (vlan_tci >> 13) & 0x07 # PCP
                        vlan_id = vlan_tci & 0x0FFF # VLAN ID
                        ethertype_after_vlan = vlan_fields[1]

                        print(f"VLAN Header Analysis:")
                        print(f" Raw VLAN Header: {vlan_header.hex()}")
                        print(f" PCP: {pcp}, VLAN ID: {vlan_id}, Ethertype: {hex(ethertype_after_vlan)}")
                        
                        if ethertype_after_vlan != 0x0800: # Verify if the packet is IPv4
                            print(f"Skipping packet with unexpected Ethertype after VLAN: {hex(ethertype_after_vlan)}")
                            continue

                        ip_start = 18 # VLAN header
                    else:
                        ip_start = 14 # Untagged packet

                    # Extract and validate IP header
                    ip_packet = packet[ip_start:]
                    print(f"IP Packet (raw hex): {ip_packet.hex()}")

                    # Check the length of the IP packet
                    if len(ip_packet) < 20:
                        print("Error: IP payload too short to contain a valid IP header")
                        continue

                    ip_header = ip_packet[:20]
                    ip_fields = struct.unpack("!BBHHHBBH4s4s", ip_header)
                    version_ihl = ip_fields[0]
                    version = version_ihl >> 4
                    ihl = version_ihl & 0x0F

                    if version != 4:
                        print(f"Error: Invalid IP version {version}")
                        continue

                    if ihl < 5:
                        print(f"Error: Invalid IHL {ihl}")
                        continue
                    
                    total_length = ip_fields[2]

                    src_ip = socket.inet_ntoa(ip_fields[8])
                    dest_ip = socket.inet_ntoa(ip_fields[9])

                    print(f"Packet from {src_ip} to {dest_ip}")

                    # Verify source IP
                    if src_ip != MIDDLEMAN_IP:
                        print(f"Ignoring packet from unexpected source: {src_ip}")
                        continue

                    # Extract payload
                    payload = ip_packet[20:]
                    try:
                        decoded_payload = payload.decode("utf-8").strip()
                        print(f"Decoded payload: {decoded_payload}")
                    except UnicodeDecodeError:
                        print("Error decoding payload: Payload is not valid UTF-8")
                        continue

                    try:
                        # Decode the payload and process commands
                        message = payload.decode("utf-8")
                        print(f"Decoded message on server: {message}")
                        if not message:
                            print("Empty payload received on server")
                            continue

                        buffer += message

                        print(f"Buffer before processing: {buffer}")
                        messages = buffer.split("\n")
                        print(f"Messages extracted: {messages}")

                        for msg in messages[:-1]:
                            print(f"Processing message {msg}...")
                            process_message(msg)

                        buffer = messages[-1]
                        print(f"Buffer after processing: {buffer}")
                    except Exception as e:
                        print(f"Error decoding payload: {e}")
                else:
                    print(f"Non-VLAN packet received with Ethertype: {hex(ethertype)}")

        except KeyboardInterrupt:
            print("Stopping car steering...")

        finally:
            raw_sock.close()

# Start threads for video feed and car steering
camera_thread = threading.Thread(target=camera_feed)
steering_thread = threading.Thread(target=car_steering)

camera_thread.start()
steering_thread.start()

camera_thread.join()
steering_thread.join()
