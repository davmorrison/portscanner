# portscanner

Features
--------
  * TCP Connect scan  (-sT)  — no elevated privileges required
  * TCP SYN scan       (-sS)  — requires root/admin + scapy, faster & quieter
  * Basic service banner grabbing / version hints (-sV, on by default)
  * Multi-threaded scanning
  * Flexible port specs: "22,80,443", "1-1024", "20-25,80,8000-8100"
  * A curated list of common ports used as the default / --top-ports N
  * nmap-style summary output, optional file output (-oN)

Usage
-----
    python3 portscan.py <target> [options]

Examples
--------
    python3 portscan.py 192.168.1.10
    python3 portscan.py scanme.example.com -p 1-1000
    python3 portscan.py 10.0.0.5 -p 22,80,443 -sS
    python3 portscan.py 10.0.0.0/24 --top-ports 50 -T 200
    python3 portscan.py 10.0.0.5 --no-banner -oN results.txt

Making it feel like a real command (`portscan <ip>`)
------------------------------------------------------
    chmod +x portscan.py
    sudo mv portscan.py /usr/local/bin/portscan
    portscan 192.168.1.10
