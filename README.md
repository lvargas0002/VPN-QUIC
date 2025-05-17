# Final Project for CS 5470.

This VPN utilizes QUIC-like features to create a more reliable, secure connection.

## Guide to installing picotls -

**Make sure cmake is installed :** 
```bash
sudo apt install cmake
```
**Make sure the library installer is installed:**
```bash
sudo apt install libssl-dev
```
**Run :**
```bash
sudo apt update
```
**You can also try this:**
```bash
sudo apt install cmake build-essential git libssl-dev
```
**Clone PicoTLS :**
```bash
cd ~
git clone --recursive https://github.com/h2o/picotls.git
cd picotls
cmake .
make
```
### To include in file:

#include <picotls.h> // Core PicoTLS definitions
#include <picotls/openssl.h> // OpenSSL backend integration
#include <openssl/ssl.h> // OpenSSL SSL functions

### Makefile:
To build code for server and client use the makefile. It contains a path to the required libraries for PicoTLS.

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
sudo ip tuntap add dev tun0 mode tun
sudo ip addr add 10.8.0.1/24 dev tun0
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
### Closing Server Connection

Once te server has stopped if you wish to run the server again it's important to restart as it can help prevent errors and conflicts.

```bash
sudo ip link set tun0 down
sudo ip tuntap del dev tun0 mode tun
```
