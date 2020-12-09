# Scout Network Scanning Tool
A simple yet fast network scanning tool as a first step of tinkering with scapy.
## Install the requirements:
```sh
pip3 install -r requirements.txt
```
## Scan a network:
```sh
$ sudo python3 scout.py  <STARTING_HOST> <ENDING_HOST>
```
### More Examples:
#### Simple scan:
```sh
$ sudo python3 scout.py  192.168.1.2 192.168.1.254
```
#### Scan with specified number of threads:
```sh
$ sudo python3 scout.py  192.168.1.2 192.168.1.254 --threads 130
```

#### Scan with specified ICMP timeout (in seconds):
```sh
$ sudo python3 scout.py  192.168.1.2 192.168.1.254 --timeout 13
```
