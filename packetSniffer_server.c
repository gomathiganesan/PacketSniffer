#include"pSniff.h"
int main()
{
	int sid,b,c,l,a;
	char msg[20];
	struct sockaddr_in s;
	sid=socket(AF_INET,SOCK_STREAM,0);
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
	l=listen(sid,5);
	if(l<0)
	{
		printf("Listen failed\n");
		exit(0);
	}
	a=accept(sid,S,&len);
	if(a<0)
	{
		printf("Accept failed\n");
		exit(0);
	}
	strcpy(msg,"Done");
	send(a,msg,sizeof(msg),0);
}
