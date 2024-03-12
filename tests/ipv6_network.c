#include <stdio.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winsock.h>
#pragma comment(lib, "Ws2_32.lib")

void num_to_string(char *buf, unsigned int buflen, unsigned int num)
{
	unsigned int dec = 1000000000;
	unsigned int i = 0;

	if (!buflen)
		return;

	while (dec) {
		if (!i && ((num / dec) || dec == 1))
			buf[i++] = '0' + (num / dec);
		else if (i)
			buf[i++] = '0' + (num / dec);
		if (i == buflen - 1)
			break;
		num = num % dec;
		dec /= 10;
	}
	buf[i] = '\0';
}

unsigned short our_htons(unsigned short num)
{
	return (num >> 8) | ((num & 0xFF) << 8);
}

void addr_to_string(const IN_ADDR addr, char *string)
{
	const unsigned char *chunk = (const unsigned char *)&addr;
	string[0] = '\0';
	num_to_string(string, 4, chunk[0]);
	strcat(string, ".");
	num_to_string(string+strlen(string), 4, chunk[1]);
	strcat(string, ".");
	num_to_string(string+strlen(string), 4, chunk[2]);
	strcat(string, ".");
	num_to_string(string+strlen(string), 4, chunk[3]);
}

void addr6_to_string(const IN6_ADDR addr, char *string, int max_buffer_size)
{
	inet_ntop(AF_INET6, &addr, string, max_buffer_size);
}

static BOOLEAN get_ip_port(const struct sockaddr *addr,
	char *ip, int *port, int ip_buffer_size)
{
	BOOLEAN ret = TRUE;

	if (addr == NULL)
		return FALSE;

	if (addr->sa_family == AF_INET) {
		const struct sockaddr_in *addr4 = (const struct sockaddr_in *) addr;
		addr_to_string(addr4->sin_addr, ip);
		*port = our_htons(addr4->sin_port);
	}
	else if(addr->sa_family == AF_INET6){
		const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *) addr;
		addr6_to_string(addr6->sin6_addr, ip, ip_buffer_size);
		*port = our_htons(addr6->sin6_port);
	}
	return ret;
}

int main()
{
    SOCKET s = socket(AF_INET6, SOCK_STREAM, 0);
    const char *ipv6 = "2607:f8b0:4003:c00::6a";
    struct in6_addr ipv6_buf = {0};

    struct sockaddr_in6 addr;
    addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6,ipv6,&ipv6_buf);
    addr.sin6_addr = ipv6_buf;
    addr.sin6_port = htons(0x29a);
    int status = connect(s,(struct sockaddr *) &addr, sizeof(addr));
    if(status != -1)
    {
        int counter = 0;
        int result = 0;
        do{
            Sleep(10);
            const char *fname = "log.txt";
            FILE *fp = fopen(fname, "a");
            fprintf(fp, "This file trace everything\n");
            fclose(fp);
            counter++;
            if(counter >= 50) result = 1;
        }while(result == 0);
    }
    //char ip[INET6_ADDRSTRLEN]; int port = 0;
	//get_ip_port((struct sockaddr *)&addr, ip, &port, INET6_ADDRSTRLEN);
    //const char *fname = "ipv6.txt";
    //FILE *fp = fopen(fname, "w+");
    //fprintf(fp, "%s %d\n",ip,port);
    //fclose(fp);
    //bind(s, (struct sockaddr *) &addr, sizeof(addr));
}
