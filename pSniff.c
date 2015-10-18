    #include"pSniff.h"
    int sock_raw,hisNo=0,folderNo=0;
    operation history[10];
    FILE *file;
    int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
    struct sockaddr_in source,dest;
    void print_udp_packet(unsigned char *Buffer , int Size)
    {
        
        unsigned short iphdrlen;
        
        struct iphdr *iph = (struct iphdr *)Buffer;
        iphdrlen = iph->ihl*4;
        
        struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen);
        
        fprintf(file,"\n\n***********************UDP Packet*************************\n");
        
        print_ip_header(Buffer,Size);          
        
        fprintf(file,"\nUDP Header\n");
        fprintf(file,"   |-Source Port      : %d\n" , ntohs(udph->source));
        fprintf(file,"   |-Destination Port : %d\n" , ntohs(udph->dest));
        fprintf(file,"   |-UDP Length       : %d\n" , ntohs(udph->len));
        fprintf(file,"   |-UDP Checksum     : %d\n" , ntohs(udph->check));
        
        fprintf(file,"\n");
        fprintf(file,"IP Header\n");
        PrintData(Buffer , iphdrlen);
            
        fprintf(file,"UDP Header\n");
        PrintData(Buffer+iphdrlen , sizeof udph);
            
        fprintf(file,"Data Payload\n"); 
        PrintData(Buffer + iphdrlen + sizeof udph ,( Size - sizeof udph - iph->ihl * 4 ));
        
        fprintf(file,"\n###########################################################");
    }

    void print_icmp_packet(unsigned char* Buffer , int Size)
    {
        unsigned short iphdrlen;
        
        struct iphdr *iph = (struct iphdr *)Buffer;
        iphdrlen = iph->ihl*4;
        
        struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen);
                
        fprintf(file,"**********IP-HEADER***************");
        print_ip_header(Buffer , Size);
                
        fprintf(file,"\n");
            
        fprintf(file,"ICMP Header\n");
        fprintf(file,"   |-Type : %d",(unsigned int)(icmph->type));
                
        if((unsigned int)(icmph->type) == 11)
            fprintf(file,"  (TTL Expired)\n");
        else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
            fprintf(file,"  (ICMP Echo Reply)\n");
        fprintf(file,"   |-Code : %d\n",(unsigned int)(icmph->code));
        fprintf(file,"   |-Checksum : %d\n",ntohs(icmph->checksum));
        //fprintf(logfile,"   |-ID       : %d\n",ntohs(icmph->id));
        //fprintf(logfile,"   |-Sequence : %d\n",ntohs(icmph->sequence));
        fprintf(file,"\n");

        fprintf(file,"IP Header\n");
        PrintData(Buffer,iphdrlen);
            
        fprintf(file,"UDP Header\n");
        PrintData(Buffer + iphdrlen , sizeof icmph);
            
        fprintf(file,"Data Payload\n"); 
        PrintData(Buffer + iphdrlen + sizeof icmph , (Size - sizeof icmph - iph->ihl * 4));
        
        fprintf(file,"\n###########################################################");
    }



    void ProcessPacket(unsigned char* buffer, int size)
    {
        struct iphdr *iph = (struct iphdr*)buffer;
        ++total;
        switch (iph->protocol) 
        {
            case 1:  //ICMP Protocol
                ++icmp;
		print_icmp_packet(buffer,size);
                break;
            
            case 2:  //IGMP Protocol
                ++igmp;
                break;
            
            case 6:  //TCP Protocol
                ++tcp;
		undoOrRedo(buffer,size);
                print_tcp_packet(buffer , size);
                break;
            
            case 17: //UDP Protocol
                ++udp;
		print_udp_packet(buffer,size);
                break;
            
            default: //Some Other Protocol like ARP etc.
                ++others;
                break;
        }
        printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r",tcp,udp,icmp,igmp,others,total);
    }
    void undoOrRedo(unsigned char* Buffer,int Size)
    {	int z=0,i;
	struct iphdr *iph = (struct iphdr *)Buffer;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
        char path[50]="/home/gomathi/pSniff/Folder",copy[7]="(copy)", str[5];;
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = iph->daddr;
	unsigned short iphdrlen;
        iphdrlen = iph->ihl*4;
        struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);
	unsigned int srcPort=ntohs(tcph->source);
	unsigned int destPort=ntohs(tcph->dest);
	switch(destPort)
	{
        case 60000:
		z=1;
		for(i=9;i>=0;i--)
		{
			if(history[i].flag==2)
			{
				mkdir(strcat(history[i].folder,copy), 0700);
				history[hisNo].flag=1;
				history[hisNo].isFolderPresent=1;
				strcpy(history[hisNo].folder,history[i].folder);
				break;
			}	
		}
		hisNo++;
                
	break;
	case 60001:
		z=1;
		for(i=9;i>=0;i--)
		{
			if(history[i].flag==2 && history[i].isFolderPresent)
			{	remove(history[i].folder);
				history[i].isFolderPresent=0;
				history[hisNo].flag=-1;
				history[hisNo].isFolderPresent=0;
				strcpy(history[hisNo].folder,history[i].folder);
				break;
			}	
		}
		hisNo++;
	break;
	case 60002:
		z=1;
		history[hisNo].flag=2;
		history[hisNo].isFolderPresent=1;
		sprintf(str,"%d", folderNo);
		strcpy(history[hisNo].folder,strcat(path,str));
		mkdir(history[hisNo].folder,0700);
		hisNo++;
		folderNo++;
	break;
	}
	if(z==1 && hisNo>9)
	{
		for(i=9;i>=1;i--)
		{
			history[i-1].flag=history[i].flag;
			strcpy(history[i-1].folder,history[i].folder);
		}
		hisNo=9;
     	}
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

    void packetSniffer()
    {
        int saddr_size , data_size;
        struct sockaddr saddr;
        struct in_addr in;
	
        
        unsigned char *buffer = (unsigned char *)malloc(65536); 
        
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
    }
