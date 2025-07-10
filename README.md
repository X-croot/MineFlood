🎯 Purpose of This Tool

MineFlood was developed specifically for testing the performance, resilience, and UDP handling of Minecraft servers under controlled conditions. It allows administrators, developers, and security testers to:

![DDoS Animation](https://media.tenor.com/sGQm2yFDpv0AAAAM/ddos-game.gif) ![Preview](https://i.imgur.com/6QlGJ1k.gif)


Simulate realistic or randomized UDP traffic,

Measure how their Minecraft servers handle large amounts of packet flow,

Identify potential weaknesses in network configuration or DDoS protection,

Test rate limiting, firewall rules, and anti-bot systems.

 🧠 IP Spoofing Support: Optionally simulate traffic from spoofed (fake) IP addresses.

🔢 Multithreading: Run multiple concurrent sending threads for high-load testing.

📊 Live Traffic Statistics: View real-time stats including total packets sent, data volume (KB), and sending speed (KB/s).

🖥️ User-Friendly Interface: Modern and clean GUI built with PyQt5.




📁 File Descriptions

    mineflood.py: Main application file

    styles.css: (Optional) Custom UI stylesheet/theme

    icon.png: Application icon and banner image


📦 Requirements

Python 3.x

pip3 (Python package manager)

PyQt5 library

Root privileges (required for raw socket usage)


    ### 🚀 Quick Start

```bash
git clone https://github.com/X-croot/MineFlood.git
cd mineflood
pip install -r requirements.txt
sudo python3 mineflood.py
```





🔐 Legal Disclaimer

WARNING: This tool is intended solely for use in authorized testing environments. Do not use it against any server, network, or system without explicit and written permission from the system owner. The developer cannot be held responsible for any misuse or damage caused by this tool. Using this software is entirely at your own risk and responsibility.
