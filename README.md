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


If using Geany:
Drop down Build and select Set Build Commands.
Change compile to: gcc -Wall -I/home/robotics/picotls/include -c "%f"
Change Build to: gcc -Wall \ -I/home/robotics/picotls/include \ /home/robotics/picotls/lib/picotls.c \ /home/robotics/picotls/lib/openssl.c \ /home/robotics/picotls/lib/hpke.c \ "%f" \ -o "%e" \ -lssl -lcrypto


To include in file:
#include <picotls.h>             // Core PicoTLS definitions
#include <picotls/openssl.h>     // OpenSSL backend integration
#include <openssl/ssl.h>         // OpenSSL SSL functions


