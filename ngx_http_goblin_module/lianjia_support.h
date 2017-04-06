#ifndef LIANJIA_SUPPORT_H
#define LIANJIA_SUPPORT_H

#include <stdint.h>
#include <sys/socket.h>

#include <ngx_http.h>
#define DEFAULT_UCID_SIZE 36

uint64_t security_lianjia_get_ucid(ngx_http_request_t *r);

int ngx_module_lianjia_get_client_addr(ngx_http_request_t *, struct sockaddr*, socklen_t);

int ngx_module_lianjia_get_real_client_addr(ngx_http_request_t *, struct sockaddr*, socklen_t);

#endif

