🎯 Purpose of This Tool

MineFlood was developed specifically for testing the performance, resilience, and UDP handling of Minecraft servers under controlled conditions. It allows administrators, developers, and security testers to:

![Preview](https://media.tenor.com/Ufy_tbBg32YAAAAM/spin-villager.gif)


Simulate realistic or randomized UDP traffic,

Measure how their Minecraft servers handle large amounts of packet flow,

Identify potential weaknesses in network configuration or DDoS protection,

Test rate limiting, firewall rules, and anti-bot systems.

<img width="855" height="668" alt="resim" src="https://github.com/user-attachments/assets/deabb99a-800e-41a8-a64b-0c89073c759c" />


 🧠 IP Spoofing Support: Optionally simulate traffic from spoofed (fake) IP addresses.

🔢 Multithreading: Run multiple concurrent sending threads for high-load testing.

📊 Live Traffic Statistics: View real-time stats including total packets sent, data volume (KB), and sending speed (KB/s).

🖥️ User-Friendly Interface: Modern and clean GUI built with PyQt5.

🕵️‍♂️ IP Spoofing

The application offers a strong IP spoofing engine. You can configure each of the four octets of an IP address manually:

    Entering r will use a random number from 1 to 255.
    A range like 50-100 will choose a number between 50 and 100.
    A single number like 168 will fix that octet to that value.

📦 Payload Options

You can choose the payload content mode:

    Raw: Sends completely random bytes.
    Base64: Sends Base64-encoded random data.

You also define a minimum and maximum size (in bytes). Each packet will randomly choose a size in that range, making traffic look unpredictable and realistic.


📁 File Descriptions

    mineflood.py: Main application file

    styles.css: Custom UI stylesheet/theme

    icon.png: Application icon and banner image


📦 Requirements

Python 3.x

pip3 (Python package manager)

PyQt5 library

Root privileges (required for raw socket usage)


```bash
git clone https://github.com/X-croot/MineFlood.git
cd mineflood
pip install -r requirements.txt
sudo python3 mineflood.py
```





🔐 Legal Disclaimer

WARNING: This tool is intended solely for use in authorized testing environments. Do not use it against any server, network, or system without explicit and written permission from the system owner. The developer cannot be held responsible for any misuse or damage caused by this tool. Using this software is entirely at your own risk and responsibility.
