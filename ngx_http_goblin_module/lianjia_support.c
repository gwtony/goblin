#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "lianjia_support.h"


int ngx_module_lianjia_get_client_addr(ngx_http_request_t *req, struct sockaddr *addr, socklen_t len)
{
	struct sockaddr_in *inet_ptr=(void*)addr;

	if (req->connection->sockaddr->sa_family != addr->sa_family) {
		// Address family not supported.
		return -EINVAL;
	}
	if (req->connection->sockaddr->sa_family!=AF_INET) {
		// Address family not supported.
		return -EINVAL;
	}
	inet_ptr->sin_family = ((struct sockaddr_in*)(req->connection->sockaddr))->sin_family;
	inet_ptr->sin_addr.s_addr = ((struct sockaddr_in*)(req->connection->sockaddr))->sin_addr.s_addr;
	inet_ptr->sin_port = ((struct sockaddr_in*)(req->connection->sockaddr))->sin_port;
	return 0;
}

static void ngx_str_trim(ngx_str_t *s)
{
	for (;*(s->data)==' ' && s->len>0; s->data++, s->len--);    // Skip head spaces.
	for (;s->data[s->len-1]==' ' && s->len>0; s->len--);        // Skip tail spaces.
}

static ngx_array_t *xff_breakdown (ngx_http_request_t *r)
{
	ngx_uint_t n;
	ngx_table_elt_t  **h;
	ngx_array_t *ret;
	ngx_str_t *str, token, all;
	ngx_uint_t p;

	n = r->headers_in.x_forwarded_for.nelts;
	if (n>1) {
		return NULL;
	}
    h = r->headers_in.x_forwarded_for.elts;

	if (h == NULL || *h==NULL) {
		return NULL;
	} else {
		ret = ngx_array_create(r->pool, 16, sizeof(ngx_str_t));

		all.data = h[0]->value.data;
		all.len = h[0]->value.len;
		token.data = all.data;
		token.len = 0;
		for (p=0; p<all.len; ++p) {
			if (all.data[p] == ',') {
				ngx_str_trim(&token);
				if (token.len > 0) {
					str = ngx_array_push(ret);
					str->data = token.data;
					str->len = token.len;
				}
				token.data = all.data + p+1;
				token.len = 0;
			} else {
				token.len++;
			}
		}
		ngx_str_trim(&token);
		if (token.len > 0) {
			str = ngx_array_push(ret);
			str->data = token.data;
			str->len = token.len;
		}

		return ret;
	}
}

int ngx_module_lianjia_get_real_client_addr(ngx_http_request_t *req, struct sockaddr *addr, socklen_t len)
{
    ngx_array_t *arr;
	ngx_str_t *value;
	struct sockaddr_in *inet_ptr;
	char ip[16];

	if (req->connection->sockaddr->sa_family != addr->sa_family) {
		return -EINVAL;
	}
	inet_ptr = (void*)addr;
	if (req->connection->sockaddr->sa_family!=AF_INET) {
		// Address family not supported.
		return -EINVAL;
	}
	if (req->headers_in.x_forwarded_for.nelts == 0) {
		return -ENOENT;
	}

	arr = xff_breakdown(req);
	if (arr == NULL) {
		return -EINVAL;
	}

	value = arr->elts;
	if (value[arr->nelts-1].len > 16) {
		return -EINVAL;
	}

	memset(ip, 0, 16);
	strncpy(ip, (const char *)value[arr->nelts-1].data, value[arr->nelts-1].len);
	if (inet_aton(ip, &inet_ptr->sin_addr) == 0)
		return -EINVAL;

	return 0;
	
	//Test Code:
	//inet_aton("1.2.3.4", &inet_ptr->sin_addr);
	//inet_ptr->sin_port = 0;
	return 0;
}


//The same as peerip module
static ngx_str_t
security_get_header(ngx_http_request_t *r, ngx_str_t *key) {
	ngx_str_t	ret;
    ngx_list_part_t            *part;
    ngx_table_elt_t            *h;
    ngx_uint_t                  i;

    /*
    Get the first part of the list. There is usual only one part.
    */
    part = &r->headers_in.headers.part;
    h = part->elts;

    /*
    Headers list array may consist of more than one part,
    so loop through all of it
    */
    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                /* The last part, search is done. */
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        /*
        Just compare the lengths and then the names case insensitively.
        */
        if (key->len != h[i].key.len || ngx_strcasecmp(key->data, h[i].key.data) != 0) {
            /* This header doesn't match. */
            continue;
        }

        /*
        Ta-da, we got one!
        Note, we'v stop the search at the first matched header
        while more then one header may fit.
        */
		ret.data = h[i].value.data;
		ret.len = h[i].value.len;
        return ret;
    }

    /*
    No headers was found
    */
	ret.data = NULL;
	ret.len = 0;
    return ret;
}

static uint32_t security_crc32_for_byte(uint32_t r) {
	int j;
	for(j = 0; j < 8; ++j)
		r = (r & 1? 0: (uint32_t)0xEDB88320UL) ^ r >> 1;
	return r ^ (uint32_t)0xFF000000UL;
}

static uint32_t security_local_crc32(const void *data, size_t n_bytes) {
	static uint32_t table[0x100];
	size_t i;
	uint32_t crc=0;

	if(!*table)
		for(i = 0; i < 0x100; ++i)
			table[i] = security_crc32_for_byte(i);
	for(i = 0; i < n_bytes; ++i)
		crc = table[(uint8_t)crc ^ ((uint8_t*)data)[i]] ^ crc >> 8;

	return crc;
}


uint64_t
security_lianjia_get_ucid(ngx_http_request_t *r)
{
	ngx_str_t token_cookie_name = ngx_string("lianjia_token");
	ngx_str_t token_header_name_old = ngx_string("LIANJIA_ACCESS_TOKEN");
	ngx_str_t token_header_name = ngx_string("LIANJIA-ACCESS-TOKEN");
	ngx_str_t token;
	ngx_str_t str_magic, str_e_ucid, str_salt, str_crc;
	uint64_t e_ucid, ucid;
	uint32_t salt, crc, local_crc;
	char tmp[DEFAULT_UCID_SIZE];
	int len;

	// Get token
	if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &token_cookie_name, &token)
			== NGX_DECLINED) {
		token = security_get_header(r, &token_header_name);
		if (token.data == NULL) {
			token = security_get_header(r, &token_header_name_old);
			if (token.data == NULL) {
				goto error;
			}
		}
	}
	if (token.len != DEFAULT_UCID_SIZE) {
		goto error;
	}

	// Split tokens
	str_magic.data = token.data +0;
	str_magic.len = 4;
	if (ngx_memcmp(str_magic.data, "2.00", str_magic.len)!=0) {
		//fprintf(stderr, "magic is not 2.00\n");
		goto error;
	}

	str_e_ucid.data = token.data +4;
	str_e_ucid.len = 16;
	memcpy(tmp, str_e_ucid.data, str_e_ucid.len);
	tmp[str_e_ucid.len]=0;
	if (sscanf(tmp, "%llx", (long long unsigned int*)&e_ucid)<1) {
		goto error;
	}

	str_salt.data = token.data +20;
	str_salt.len = 8;
    memcpy(tmp, str_salt.data, str_salt.len);
    tmp[str_salt.len]=0;
    if (sscanf(tmp, "%x", (unsigned int*)&salt)<1) {
        goto error;
    }
	fprintf(stderr, "salt is %x\n", salt);


	str_crc.data = token.data +28;
	str_crc.len = 8;
    memcpy(tmp, str_crc.data, str_crc.len);
    tmp[str_crc.len]=0;
    if (sscanf(tmp, "%x", (unsigned int*)&crc)<1) {
        goto error;
    }

	// Checking
	len = snprintf(tmp, DEFAULT_UCID_SIZE, "%llu-_-%u", (long long unsigned int)e_ucid, (unsigned int)salt);
	local_crc =  security_local_crc32((void*)tmp, len);
	if (local_crc != crc) {
		goto error;
	}

	// return
	ucid = e_ucid ^ 0x11AA33CC22BB44DDULL ^ (((long long unsigned int)salt<<32)|(long long unsigned int)salt);

	return ucid;
error:
	return 0;
}
