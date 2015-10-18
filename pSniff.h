     
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <unistd.h>
    #include<stdio.h> 
    #include<stdlib.h>    
    #include<string.h>    
    #include<netinet/ip_icmp.h>   
    #include<netinet/udp.h>   
    #include<netinet/tcp.h>   
    #include<netinet/ip.h>    
    #include<sys/socket.h>
    #include<arpa/inet.h>
    #define DO 60002
    #define UNDO 60001
    #define REDO 60000
    #define PACKET_SIZE 65536
    typedef struct operation
    {
	    int flag,isFolderPresent;
	    char folder[256];
    }operation;

    void ProcessPacket(unsigned char* , int);
    void undoOrRedo(unsigned char* Buffer,int Size);
    void print_ip_header(unsigned char* , int);
    void print_tcp_packet(unsigned char* , int);
    void PrintData (unsigned char* , int);
    void packetSniffer();
