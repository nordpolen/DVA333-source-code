import threading
import struct
import socket
import cv2
import numpy as np
from time import perf_counter, time

# Configuration for control signals
MIDDLEMAN_HOST = "12.1.1.131" # Middleman/Gateway IP address
MIDDLEMAN_PORT = 6000 # Port used for communication with Middleman/Gateway
DEADZONE = 5000 # Joystick deadzone to avoid unintended movements
speed_factor = 0.5 # Factor to scale speed of the vehicle
joystick_device = "/dev/input/js1" # Joystick device path

# Configuration for video stream
CLIENT_IP = "0.0.0.0" # Client IP address for video reception
CLIENT_PORT = 5001 # Port for receiving video stream
MAX_PACKET_SIZE = 1200 # Maximum size of received packets in bytes
FRAME_TIMEOUT = 0.5 # Timeout for receiving complete video frames

def map_to_duty_cycle(value):
    """
    Maps joystick input values to PWM duty cycle percentages.
    Args:
    value (int): Raw joystick value.
    Returns:
    int: Corresponding duty cycle percentage.
    """
    value = max(-32768, min(32767, value)) # Clamp value to joystick range
    return int((value + 32768) / 65535 * 100) # Convert to percentage

def get_direction(x, y):
    """
    Determines the movement direction based on joystick inputs.
    Args:
        x (int): Horizontal joystick input.
        y (int): Vertical joystick input.
    Returns:
        int: Direction code (e.g., 1 for forward, -1 for backward).
    """
    if abs(x) < DEADZONE and y > DEADZONE:
        return 1 # Forward
    elif abs(x) < DEADZONE and y < -DEADZONE:
        return -1 # Backward
    elif x > DEADZONE and abs(y) < DEADZONE:
        return 2 # Right
    elif x < -DEADZONE and abs(y) < DEADZONE:
        return -2 # Left
    else:
        return 0 # Neutral/No movement

def send_steer_signals():
    """
    Reads joystick input and sends control signals to the Middleman server.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP socket
    print("Client is running...")
    try:
        with open(joystick_device, "rb") as js:
            x_value = 0
            y_value = 0

        while True:
            event = js.read(8)
            time, value, event_type, axis_or_button = struct.unpack("IhBB", event)

            if event_type == 1: # Button press
                if axis_or_button == 1 and value == 1:
                    start_time = perf_counter()
                    message = f"{start_time},0,0,0\n"
                    DSCP_VALUE = 56
                    TOS_VALUE = DSCP_VALUE << 2
                    client_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, TOS_VALUE)
                    client_socket.sendto(message.encode(), (MIDDLEMAN_HOST, MIDDLEMAN_PORT))
                    print(f"Emergency stop signal sent with DSCP: {DSCP_VALUE}.")

            elif event_type == 2: # Joystick movement
                if axis_or_button == 0:
                    x_value = value
                elif axis_or_button == 1:
                    y_value = value
                else:
                    continue

                direction = get_direction(x_value, y_value)
                left_duty_cycle = int(map_to_duty_cycle(y_value - x_value) * speed_factor)
                right_duty_cycle = int(map_to_duty_cycle(y_value + x_value) * speed_factor)
                current_time = perf_counter()
                message = f"{current_time},{left_duty_cycle},{right_duty_cycle},{direction}\n"

                DSCP_VALUE = 48
                TOS_VALUE = DSCP_VALUE << 2

                client_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, TOS_VALUE)
                client_socket.sendto(message.encode("utf-8"), (MIDDLEMAN_HOST, MIDDLEMAN_PORT))
                print(f"Sent message: {message.strip()} with DSCP: {DSCP_VALUE}.")
    finally:
        client_socket.close()
        print("Connection closed...")
def receive_camera_feed():
    """
    Receives and decodes video feed packets from the server.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.bind((CLIENT_IP, CLIENT_PORT))
    print("Client is active. Receiving video stream...")

    frame_buffer = {}
    expected_fragments = 0
    received_fragments = 0
    frame_start_time = time()
    while True:
        try:
            packet, addr = sock.recvfrom(MAX_PACKET_SIZE)
            # Extract IP header and DSCP value
            ip_header = packet[:20]
            tos = ip_header[1] # ToS is byte 1 in the IP header
            dscp = (tos >> 2) & 0x3F # Extract DSCP value

            # Extract UDP payload
            udp_payload = packet[28:]

            # Extract fragment header
            header = udp_payload[:20].decode(errors="ignore").strip()
            parts = header.split('/')

            if len(parts) < 3:
                print(f"Invalid header: {header}")
                continue

            fragment_index = int(parts[0])
            total_fragments = int(parts[1])
            fragment_data = udp_payload[20:]
            
            if received_fragments > 0 and fragment_index == 0:
                frame_buffer = {}
                expected_fragments = total_fragments
                received_fragments = 0

            if received_fragments == 0:
                frame_start_time = time()
                expected_fragments = total_fragments

            frame_buffer[fragment_index] = fragment_data
            received_fragments += 1

            if len(frame_buffer) == expected_fragments:
                frame_data = b''.join(frame_buffer[i] for i in range(expected_fragments))
                start_index = frame_data.find(b'\xff\xd8')
                if start_index == -1:
                    frame_buffer = {}
                    continue

                frame_data = frame_data[start_index:]
                if not frame_data.endswith(b'\xff\xd9'):
                    frame_buffer = {}
                    continue
                frame = cv2.imdecode(np.frombuffer(frame_data, dtype=np.uint8), cv2.IMREAD_COLOR)
                if frame is not None:
                    frame = cv2.resize(frame, (640, 480))
                    cv2.imshow("Video Feed", frame)
                    if cv2.waitKey(1) & 0xFF == ord('q'):
                        break
                frame_buffer = {}

            if time() - frame_start_time > FRAME_TIMEOUT:
                frame_buffer = {}

        except Exception as e:
            print(f"Error: {e}")
            cv2.destroyAllWindows()
            sock.close()

if __name__ == "__main__":
    """
    Main execution thread that initializes threads for sending control signals
    and receiving video feed.
    """
    thread1 = threading.Thread(target=send_steer_signals)
    thread2 = threading.Thread(target=receive_camera_feed)
    thread1.start()
    thread2.start()
    thread1.join()
    thread2.join()