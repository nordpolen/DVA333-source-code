# Real-Time Remote Vehicle Control over TSN and 5G

This project demonstrates a real-time remote-controlled vehicle system using **Time-Sensitive Networking (TSN)** and **private 5G** infrastructure. It enables low-latency video streaming and control signal transmission across a multi-node architecture.

## 🚗 System Architecture

The project consists of three main components:

### 1. Client (`client.py`)
- Sends steering commands via joystick over UDP.
- Receives and displays MJPEG video stream from the server.

### 2. Gateway / Middleman (`enhanced_gateway.py`)
- Translates DSCP to PCP for VLAN tagging.
- Routes control commands and video stream between client and server.
- Reassembles and re-fragments JPEG frames for UDP transmission.

### 3. Server / Vehicle (`server.py`)
- Captures and encodes video using onboard camera.
- Sends VLAN-tagged Ethernet frames to the gateway.
- Receives and interprets steering commands to control GPIO and PWM.

---

## 🧠 Features

- Real-time steering control using joystick input.
- Low-latency MJPEG video feed from the robot.
- DSCP ↔ PCP translation for QoS-aware routing.
- Ethernet frame manipulation with raw sockets.
- UDP packet fragmentation and reassembly for video streaming.

---

## 🛠️ Technologies

- Python 3.x
- OpenCV
- Raw and UDP socket programming
- VLAN, PCP, DSCP (QoS)
- GPIO & PWM (on server side)
- Threading and concurrency

---

## 📦 Requirements

- Linux OS with root access (for raw socket and GPIO control).
- Python 3.6 or higher.
- Dependencies:
  - `opencv-python`
  - `numpy`

- Hardware:
  - Joystick (e.g. PS4 controller)
  - Raspberry Pi or embedded Linux device (robot car)
  - TSN switch and 5G gateway
  - Laptop or PC (client)

---

## 📁 File Overview

| File               | Description                                                         |
|--------------------|----------------------------------------------------------------------|
| `client.py`        | Sends joystick-based steering commands and displays video stream.    |
| `enhanced_gateway.py` | Middleman that handles DSCP-PCP mapping and routes traffic.        |
| `server.py`        | Server-side logic for camera capture and car movement control.       |

---

## 🖥️ How to Run

### On the Server (Robot Car):
sudo python3 server.py

### On the Gateway:
sudo python3 enhanced_gateway.py

### On the Client:
python3 client.py

**Note:** Root permissions may be required for raw sockets and GPIO access.

## 🖼️ System Topology
[Joystick + Display] | Client | 5G Network | Gateway | TSN Switch | Server (Robot Car)


## 📚 Future Improvements and Advancements

- Integrate AI-based object detection and autonomous driving.
- Add gPTP support for time synchronization.
- Web-based dashboard for monitoring and remote control.
- Support for multiple vehicles.

## 👩‍💻 Authors

Created by **Josefina Nord** and **William Rosales** as part of a real-time robotics and networking thesis using TSN and 5G.
