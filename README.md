# Final Project for CS 5470.

This VPN utilizes QUIC-like features to create a more reliable, secure connection.

## Guide to installing picotls -

**Make sure cmake is installed :** sudo apt install cmake
**Make sure the library installer is installed:** sudo apt install libssl-dev

**Run :** sudo apt update
**You can also try this:** sudo apt install cmake build-essential git libssl-dev

**Run the Following :**
cd ~
git clone --recursive https://github.com/h2o/picotls.git
cd picotls
cmake .
make

> [!IMPORTANT]
> To compile client file: **change to the path you have for these files**

gcc -Wall \ -I/home/robotics/picotls/include \ /home/robotics/picotls/lib/picotls.c \ /home/robotics/picotls/lib/openssl.c \ /home/robotics/picotls/lib/hpke.c \ client.c \ -o client \ -lssl -lcrypto

**If using Geany:**
Drop down Build and select Set Build Commands.
Change compile to: gcc -Wall -I/home/robotics/picotls/include -c "%f"
Change Build to: gcc -Wall \ -I/home/robotics/picotls/include \ /home/robotics/picotls/lib/picotls.c \ /home/robotics/picotls/lib/openssl.c \ /home/robotics/picotls/lib/hpke.c \ "%f" \ -o "%e" \ -lssl -lcrypto

### To include in file:

#include <picotls.h> // Core PicoTLS definitions
#include <picotls/openssl.h> // OpenSSL backend integration
#include <openssl/ssl.h> // OpenSSL SSL functions

## Installing OpenVPN

By default, the open vpn source code is on the gitignore due to size limitations on github repos.

First, start off by installing the openvpn source code by running the following command

```bash
git clone https://github.com/OpenVPN/openvpn.git
```

Next install OpenVPN dependencies, for example on a Debian/Ubuntu system run the following:

```bash
sudo apt update
sudo apt install build-essential libssl-dev libcap-dev pkg-config
```

Next build and install the OpenVPN source code:

```
cd openvpn
./configure
make
sudo make install
```

### Setting up the TUN Interface

Run the following commands to create and configure the TUN device:

```bash
sudo ip link add dev tun0 type tun
sudo ip address add 10.8.0.1/24 dev tun0
sudo ip link set dev tun0 up
```

### Setting The IP Forwarding

For the server to forward the traffic through the interface, enable IP forwarding:

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

Finally adding the routing table to ensure the traffic is routed through the TUN device:

```bash
sudo ip route add 10.8.0.0/24 dev tun0
```

### Checking Connectivity

Once tunnel is running, you can do a sanity check by pinging the server from the client

```bash
ping 10.8.0.1
```
