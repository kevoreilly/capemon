#include <stdio.h>
#include <windows.h>
#include <wininet.h>

int print_url_contents(const char *url)
{
    HINTERNET internet_handle, request_handle;
    char buffer[1024]; unsigned long bytes_read;

    internet_handle = InternetOpen(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL,
        NULL, 0);
    if(internet_handle == NULL)  return FALSE;

    request_handle = InternetOpenUrl(internet_handle, url, NULL, 0, 0, 0);
    if(request_handle == NULL) {
        InternetCloseHandle(internet_handle);
        return FALSE;
    }

    while (InternetReadFile(request_handle, buffer, sizeof(buffer),
            &bytes_read) != FALSE && bytes_read != 0) {
        fwrite(buffer, bytes_read, 1, stderr);
    }

    InternetCloseHandle(internet_handle);
    InternetCloseHandle(request_handle);
    return TRUE;
}

int main()
{
    print_url_contents("http://jbremer.org/");
}
