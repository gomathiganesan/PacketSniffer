    #include<stdio.h> 
    #include<stdlib.h>    
    #include<string.h>    
    #include<netinet/ip_icmp.h>   
    #include<netinet/udp.h>   
    #include<netinet/tcp.h>   
    #include<netinet/ip.h>    
    #include<sys/socket.h>
    #include<arpa/inet.h>

    void ProcessPacket(unsigned char* , int);
    void print_ip_header(unsigned char* , int);
    void print_tcp_packet(unsigned char* , int);
    void PrintData (unsigned char* , int);

    int sock_raw;
    FILE *file;
    int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
    struct sockaddr_in source,dest;

    int main()
    {
        int saddr_size , data_size;
        struct sockaddr saddr;
        struct in_addr in;
        
        unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
        
        file=fopen("packetDetails.txt","w");
        if(file==NULL) 
		printf("Unable to create file.");
        sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
        if(sock_raw < 0)
        {
            printf("Socket Error\n");
            return 1;
        }
        while(1)
        {
            saddr_size = sizeof(saddr);
            data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
            if(data_size <0 )
            {
                printf("Failed to get packets\n");
                return 1;
            }
            ProcessPacket(buffer , data_size);
        }
        close(sock_raw);
        printf("Finished");
        return 0;
    }

    void ProcessPacket(unsigned char* buffer, int size)
    {
        struct iphdr *iph = (struct iphdr*)buffer;
        ++total;
        switch (iph->protocol) 
        {
            case 1:  //ICMP Protocol
                ++icmp;
                break;
            
            case 2:  //IGMP Protocol
                ++igmp;
                break;
            
            case 6:  //TCP Protocol
                ++tcp;
                print_tcp_packet(buffer , size);
                break;
            
            case 17: //UDP Protocol
                ++udp;
                break;
            
            default: //Some Other Protocol like ARP etc.
                ++others;
                break;
        }
        printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r",tcp,udp,icmp,igmp,others,total);
    }

    void print_ip_header(unsigned char* Buffer, int Size)
    {
        unsigned short iphdrlen;
            
        struct iphdr *iph = (struct iphdr *)Buffer;
        iphdrlen =iph->ihl*4;
        
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr;
        
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = iph->daddr;
        
        fprintf(file,"\n");
        fprintf(file,"IP Header\n");
        fprintf(file,"   |-IP Version        : %d\n",(unsigned int)iph->version);
        fprintf(file,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
        fprintf(file,"   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
        fprintf(file,"   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
        fprintf(file,"   |-Identification    : %d\n",ntohs(iph->id));
        fprintf(file,"   |-TTL      : %d\n",(unsigned int)iph->ttl);
        fprintf(file,"   |-Protocol : %d\n",(unsigned int)iph->protocol);
        fprintf(file,"   |-Checksum : %d\n",ntohs(iph->check));
        fprintf(file,"   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
        fprintf(file,"   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
    }

    void print_tcp_packet(unsigned char* Buffer, int Size)
    {
        unsigned short iphdrlen;
        
        struct iphdr *iph = (struct iphdr *)Buffer;
        iphdrlen = iph->ihl*4;
        
        struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);
                
        fprintf(file,"\n\n***********************TCP Packet*************************\n");   
            
        print_ip_header(Buffer,Size);
            
        fprintf(file,"\n");
        fprintf(file,"TCP Header\n");
        fprintf(file,"   |-Source Port      : %u\n",ntohs(tcph->source));
        fprintf(file,"   |-Destination Port : %u\n",ntohs(tcph->dest));
        fprintf(file,"   |-Sequence Number    : %u\n",ntohl(tcph->seq));
        fprintf(file,"   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
        fprintf(file,"   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
        fprintf(file,"   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
        fprintf(file,"   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
        fprintf(file,"   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
        fprintf(file,"   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
        fprintf(file,"   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
        fprintf(file,"   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
        fprintf(file,"   |-Window         : %d\n",ntohs(tcph->window));
        fprintf(file,"   |-Checksum       : %d\n",ntohs(tcph->check));
        fprintf(file,"   |-Urgent Pointer : %d\n",tcph->urg_ptr);
        fprintf(file,"\n");
        fprintf(file,"                        DATA Dump                         ");
        fprintf(file,"\n");
            
        fprintf(file,"IP Header\n");
        PrintData(Buffer,iphdrlen);
            
        fprintf(file,"TCP Header\n");
        PrintData(Buffer+iphdrlen,tcph->doff*4);
            
        fprintf(file,"Data Payload\n"); 
        PrintData(Buffer + iphdrlen + tcph->doff*4 , (Size - tcph->doff*4-iph->ihl*4) );
                            
        fprintf(file,"\n###########################################################");
    }


    void PrintData (unsigned char* data , int Size)
    {
        
        for(i=0 ; i < Size ; i++)
        {
            if( i!=0 && i%16==0)   
            {
                fprintf(file,"         ");
                for(j=i-16 ; j<i ; j++)
                {
                    if(data[j]>=32 && data[j]<=128)
                        fprintf(file,"%c",(unsigned char)data[j]); 
                    
                    else fprintf(file,"."); 
                }
                fprintf(file,"\n");
            }
            
            if(i%16==0) fprintf(file,"   ");
                fprintf(file," %02X",(unsigned int)data[i]);
                    
            if( i==Size-1)  
            {
                for(j=0;j<15-i%16;j++) fprintf(file,"   "); 
                
                fprintf(file,"         ");
                
                for(j=i-i%16 ; j<=i ; j++)
                {
                    if(data[j]>=32 && data[j]<=128) fprintf(file,"%c",(unsigned char)data[j]);
                    else fprintf(file,".");
                }
                fprintf(file,"\n");
            }
        }
    }

