#include"pSniff.h"
int main()
{
	int sid,b,c;
	char msg[20];
	struct sockaddr_in s;
	sid=socket(AF_INET,SOCK_STREAM,0);
	packetSniffer();
	if(sid<0)
	{
		printf("Socket not created\n");
		exit(0);
	}
	s.sin_family=AF_INET;
	s.sin_port=htons(DO);
	s.sin_addr.s_addr=htonl(INADDR_ANY);
	struct sockaddr* S=(struct sockaddr*)&s;
	int len=sizeof(s);
	b=bind(sid,S,&len);
	if(b<0)
	{
		printf("Bind error\n");
		exit(0);
	}
	c=connect(sid,S,len);
	if(c<0)
	{
		printf("Connection establishment failed\n");
		exit(0);
	}
	recv(sid,msg,sizeof(msg),0);
	printf("Server's response :%s\n",msg);
}
