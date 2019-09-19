#include "../include/uv.h"

#include <stdlib.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"
#endif
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    size_t len = size + 1;
    char *str = (char*)malloc(len);
    str[size] = '\0';

    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;

    int port = 12345;

    uv_ip4_addr(str, port, &addr4);
    uv_ip6_addr(str, port, &addr6);

    return 0;
}
