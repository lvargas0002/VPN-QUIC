#include <arpa/inet.h>  //Networking functions like inet_pton(), htons()
#include <netinet/in.h> //Defines Internet address structures.
#include <stdio.h>      //Standard I/O functions like printf()
#include <stdlib.h>     //Standard functions like exit()
#include <string.h>     //String operations like memset() and strlen()
#include <sys/socket.h> //Defines core socket functions and constants.
#include <unistd.h>     //POSIX OS functions like close()

// Defines the port number (8080) on which the server will listen for
// connections. #define creates a symbolic constant. We can use PORT wherever we
// would like to specify the port number.

#define PORT 8080 // Port number

struct quick_packet {
  int stream_id;
  int length;
  int payload[];
};
