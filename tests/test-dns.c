#define _WIN32_WINNT 0x0501
#include <stdio.h>
#include <windows.h>
#include <windns.h>
#include <ws2tcpip.h>

int main()
{
    LoadLibrary("../cuckoomon.dll");

    printf("DnsQuery -> %d\n", DnsQuery("jbremer.org", DNS_TYPE_A,
        DNS_QUERY_STANDARD, NULL, NULL, NULL));

    struct addrinfo *info = NULL;
    printf("getaddrinfo -> %d\n", getaddrinfo("jbremer.org", NULL, NULL,
        &info));

    printf("gethostbyname -> %p\n", gethostbyname("jbremer.org"));
}
