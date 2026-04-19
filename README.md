# SDN Firewall using Ryu Controller

## Project Description
This project implements a simple firewall using Software Defined Networking (SDN).

The firewall blocks insecure remote access protocols:
- Telnet (Port 23)
- SSH (Port 22)

Traffic from IP address 10.0.0.1 to these ports is dropped using OpenFlow rules.

## Technologies Used
- Python
- Ryu Controller
- OpenFlow Protocol
- Mininet Network Emulator

## How it Works
1. The Ryu controller connects to the OpenFlow switch.
2. The controller installs flow rules in the switch.
3. Normal traffic is allowed.
4. SSH and Telnet traffic from 10.0.0.1 is blocked.

## Files
- firewall.py → main SDN firewall controller code

## Author
Tharunyah
