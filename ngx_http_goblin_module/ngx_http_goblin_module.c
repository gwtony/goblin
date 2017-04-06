#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <string.h>
#include <errno.h>
#include <alloca.h>

#include "goblin_ruleset.h"
#include "lianjia_support.h"

#define	SHM_NAME	"Goblin Rule Set"
typedef struct {
	ngx_str_t	shm_path;
} ngx_http_goblin_conf_t;

typedef struct {
	ngx_flag_t done : 1;
	ngx_flag_t waiting_more_body : 1;
} ngx_http_goblin_input_ctx_t;

static struct goblin_ruleset_st *shared_ruleset=NULL;

static ngx_int_t goblin_worker_init(ngx_cycle_t *cycle);

static ngx_int_t ngx_http_goblin_preconf(ngx_conf_t *cf);
static ngx_int_t ngx_http_goblin_postconf(ngx_conf_t *cf);
static void *ngx_http_goblin_create_conf(ngx_conf_t *cf);
static char *ngx_http_goblin_merge_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t goblin_add_variables(ngx_conf_t *cf);

static char *ngx_http_goblin_admin(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_goblin_shm_path(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t goblin_punish_get (ngx_http_request_t *, ngx_http_variable_value_t *, uintptr_t);


static ngx_command_t ngx_http_goblin_commands[] = {
    { ngx_string("goblin_shm_path"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_goblin_shm_path,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("goblin_admin"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_goblin_admin,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

// 自定义内置变量
static ngx_http_variable_t goblin_variables[] = {
    { ngx_string("goblin_punish"),
        NULL, goblin_punish_get,
        0,
        0,
        0
    },
    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_http_module_t  ngx_http_goblin_module_ctx = {
    ngx_http_goblin_preconf,		/* preconfiguration */
    ngx_http_goblin_postconf,       /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_goblin_create_conf,      /* create location configuration */
    ngx_http_goblin_merge_conf        /* merge location configuration */
};

ngx_module_t  ngx_http_goblin_module = {
    NGX_MODULE_V1,
    &ngx_http_goblin_module_ctx,   /* module context */
    ngx_http_goblin_commands,      /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    goblin_worker_init,            /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t goblin_worker_init(ngx_cycle_t *cycle)
{
	if (shared_ruleset!=NULL) {
		//my_mut_diag_fix(&shared_ruleset->mut);
		//TODO: clean lock
	}
	return NGX_OK;
}

static char *parse_url_arg_delete(ngx_str_t *arg, struct goblin_rule_st *result)
{
	char *tok, *str, *pos;
	char *key, *val, *eq;
	uint32_t tmp;

	str = alloca(arg->len+1);
	memcpy(str, arg->data, arg->len);
	str[arg->len] = '\0';

	result->punish = 0;
	result->ip = 0;
	result->ucid = 0;

	pos = str;
	while ((tok=strsep(&pos, "&\r\n"))!=NULL) {
		key = tok;
		if ((eq=strchr(tok, '='))) {
			*eq = '\0';
			val = eq+1;
			if (strcmp(key, "ucid")==0) {
				if (strlen(val) <=0 || strlen(val) > DEFAULT_UCID_SIZE) {
					return "incomplete";
				}
				result->ucid = strtoull(val, NULL, 10);
			} else if (strcmp(key, "ip")==0) {
				inet_aton(val, (void*)(&tmp));
				result->ip = htonl(tmp);
			} else {
				// Unknown token.
				return key;
			}
		} else {
			return tok;
		}
	}

	if ((result->ucid == 0) && (result->ip == 0)) {
		return "incomplete";
	}

	return NULL;
}
static char *parse_url_arg(ngx_str_t *arg, struct goblin_rule_st *result)
{
	char *tok, *str, *pos;
	char *key, *val, *eq;
	uint32_t tmp;

	str = alloca(arg->len+1);
	memcpy(str, arg->data, arg->len);
	str[arg->len] = '\0';

	result->punish = 0;
	result->ip = 0;
	result->ucid = 0;

	pos = str;
	while ((tok=strsep(&pos, "&\r\n"))!=NULL) {
		key = tok;
		if ((eq=strchr(tok, '='))) {
			*eq = '\0';
			val = eq+1;
			if (strcmp(key, "ucid")==0) {
				if (strlen(val) <=0 || strlen(val) > DEFAULT_UCID_SIZE) {
					return "incomplete";
				}
				result->ucid = strtoull(val, NULL, 10);
			} else if (strcmp(key, "ip")==0) {
				inet_aton(val, (void*)(&tmp));
				result->ip = htonl(tmp);
			} else if (strcmp(key, "punish")==0) {
				if (strncmp(CAPTCHA_STR, val, strlen(CAPTCHA_STR)) == 0) {
					result->punish = CAPTCHA;
				} else if (strncmp(LOGIN_STR, val, strlen(LOGIN_STR)) == 0) {
					result->punish = LOGIN;
				} else if (strncmp(FORBIDDEN_STR, val, strlen(FORBIDDEN_STR)) == 0) {
					result->punish = FORBIDDEN;
				} else {
					return "incomplete";
				}
			} else if (strcmp(key, "expire")==0) {
				result->expire = strtoull(val, NULL, 10);
			} else {
				// Unknown token.
				return key;
			}
		} else {
			return tok;
		}
	}

	if (result->punish == 0 || ((result->ucid == 0) && (result->ip == 0))) {
		return "incomplete";
	}

	return NULL;
}


static ngx_buf_t *request_reply(ngx_http_request_t *r, ngx_int_t code, const char *string)
{
	ngx_buf_t *buf;
	static ngx_str_t reply;
	
	reply.data = (void*)string;
	reply.len = strlen(string);

	r->headers_out.status = code;
	r->headers_out.content_length_n = reply.len;
	r->headers_out.content_type.data = (void*)"text/plain";
	r->headers_out.content_type.len = strlen("text/plain");


	buf = ngx_pcalloc(r->pool, sizeof(*buf));
	if (buf==NULL) {
		return NULL;
	}

	buf->pos = reply.data;
	buf->last = reply.data + reply.len;
	buf->memory = 1;
	buf->last_buf = 1;

	return buf;
}

static ngx_int_t ngx_http_goblin_handler_add(ngx_http_request_t *r)
{
	ngx_int_t ret;
	ngx_log_t *log;
	ngx_chain_t out;
	struct goblin_rule_st rule;
	char *errstr;

    log = r->connection->log;

	switch (r->method) {
		case NGX_HTTP_GET:
		case NGX_HTTP_HEAD:
			ret = ngx_http_discard_request_body(r);
			if (ret != NGX_OK) {
				return ret;
			}

			if ((errstr = parse_url_arg(&r->args, &rule))) {
				ngx_log_error(NGX_LOG_ERR, log, 0, "[goblin_module]: Request failed: <%s>", errstr);
				return NGX_HTTP_BAD_REQUEST;
			}

			ret = ruleset_rules_atomic_add(shared_ruleset, &rule);
			if (ret != 0) {
				ngx_log_error(NGX_LOG_ERR, log, 0, "[goblin_module]: Insert rule failed");
				if (ret == -1) {
					return NGX_HTTP_INSUFFICIENT_STORAGE;
				}
				if (ret == -2) {
					return NGX_HTTP_CONFLICT;
				}
				if (ret == -3) {
					return NGX_HTTP_REQUEST_TIME_OUT;
				}
			} 
			ngx_log_error(NGX_LOG_INFO, log, 0, "[goblin_module]: Insert rule successfully");
			out.buf = request_reply(r, 200, "OK\r\n");
			out.next = NULL;
			ngx_http_send_header(r);
			return ngx_http_output_filter(r, &out);
			break;
		default:
			ngx_log_error(NGX_LOG_ERR, log, 0, "Invalid method.");
			return NGX_HTTP_NOT_ALLOWED;
	}
}

static ngx_int_t ngx_http_goblin_handler_del(ngx_http_request_t *r)
{
	ngx_int_t ret;
	ngx_log_t *log;
	ngx_chain_t out;
	struct goblin_rule_st rule;
	char *errstr;

    log = r->connection->log;

	switch (r->method) {
		case NGX_HTTP_GET:
		case NGX_HTTP_HEAD:
			ret = ngx_http_discard_request_body(r);
			if (ret != NGX_OK) {
				return ret;
			}

			if ((errstr = parse_url_arg_delete(&r->args, &rule))) {
				ngx_log_error(NGX_LOG_ERR, log, 0, "[goblin_module]: Request failed: <%s>", errstr);
				return NGX_HTTP_BAD_REQUEST;
			}

			ret = ruleset_rules_atomic_del(shared_ruleset, &rule);
			if (ret != 0) {
				ngx_log_error(NGX_LOG_ERR, log, 0, "[goblin_module]: Delete rule failed");
				return NGX_HTTP_NO_CONTENT;
			} 
			ngx_log_error(NGX_LOG_INFO, log, 0, "[goblin_module]: Delete rule successfully");
			out.buf = request_reply(r, 200, "OK\r\n");
			out.next = NULL;
			ngx_http_send_header(r);
			return ngx_http_output_filter(r, &out);
			break;
		default:
			ngx_log_error(NGX_LOG_ERR, log, 0, "Invalid method.");
			return NGX_HTTP_NOT_ALLOWED;
	}
}

#define	CMDSIZE	1024
static ngx_int_t
ngx_http_goblin_handler(ngx_http_request_t *r)
{
	int i;
	char cmd[CMDSIZE];

	if (r->uri.data[r->uri.len - 1] == '/') {
		return NGX_DECLINED;
	}

	for (i=r->uri.len-1;r->uri.data[i]!='/';--i);

	memset(cmd, 0, CMDSIZE);
	memcpy(cmd, r->uri.data+(i+1), r->uri.len-i-1);

	if (strncmp(cmd, "add", CMDSIZE)==0) {
		return ngx_http_goblin_handler_add(r);
	} else if (strncmp(cmd, "del", CMDSIZE)==0) {
		return ngx_http_goblin_handler_del(r);
	}
	return NGX_HTTP_BAD_REQUEST;
}

static ngx_int_t ngx_http_goblin_preconf(ngx_conf_t *cf)
{
	if (goblin_add_variables(cf) == NGX_OK) {
		return NGX_OK;
	}
	return NGX_ERROR;
}

static ngx_int_t ngx_http_goblin_postconf(ngx_conf_t *cf)
{
	return NGX_OK;
}

static void *
ngx_http_goblin_create_conf(ngx_conf_t *cf)
{
	ngx_http_goblin_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_goblin_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

	conf->shm_path.data=NULL;
	conf->shm_path.len=0;
    return conf;
}

static char *
ngx_http_goblin_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_goblin_conf_t *prev = (void*)parent;
	ngx_http_goblin_conf_t *conf = (void*)child;

	ngx_conf_merge_str_value(conf->shm_path, prev->shm_path, NULL);
    return NGX_CONF_OK;
} 

static char *
ngx_http_goblin_admin(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

	if (ngx_process == NGX_PROCESS_SIGNALLER || ngx_test_config) {
		return NGX_CONF_OK;
	}
	if (shared_ruleset==NULL) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "goblin_shm_path has not been set.");
		return NGX_CONF_ERROR;
	}

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_goblin_handler;

    return NGX_CONF_OK;
}

static char *ngx_http_goblin_shm_path(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	int shm_fd;
	ngx_str_t *args;
	ngx_http_goblin_conf_t *gcf;

	gcf = conf;
	args = cf->args->elts;

	if (ngx_process == NGX_PROCESS_SIGNALLER) {
		ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "Signaller, ignore goblin shared memory operation.");
		return NGX_CONF_OK;
	}
	if (ngx_test_config) {
		ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "Test config, ignore goblin shared memory operation.");
		return NGX_CONF_OK;
	}
	if (shared_ruleset == NULL) {
		ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "Creating shared memory...");
		gcf->shm_path = args[1];

		shm_fd = shm_open((void*)gcf->shm_path.data, O_RDWR|O_CREAT, 0600);
		if (shm_fd<0) {
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "Open shared memory failed: %s", strerror(errno));
			return NGX_CONF_ERROR;
		}
		if (ftruncate(shm_fd, sizeof(struct goblin_ruleset_st))<0) {
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "Set shared memory size failed: %s", strerror(errno));
			close(shm_fd);
			return NGX_CONF_ERROR;
		}
		shared_ruleset = mmap(NULL, sizeof(struct goblin_ruleset_st), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_LOCKED, shm_fd, 0);
		if (shared_ruleset==MAP_FAILED) {
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "mmap shared mempry failed: %s", strerror(errno));
			return NGX_CONF_ERROR;
		}
		close(shm_fd);
		ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "Shared memory created.");
		ruleset_init(shared_ruleset);
	} else {
		ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "Shared memory has been created before.");
	}
	return NGX_CONF_OK;
}

static ngx_int_t goblin_add_variables(ngx_conf_t *cf)
{
	int i;
	ngx_http_variable_t *var;

	for (i=0; goblin_variables[i].name.len>0; ++i) {
		var = ngx_http_add_variable(cf, &goblin_variables[i].name, goblin_variables[i].flags);
		if (var==NULL) {
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "goblin add variable '%s' failed.", goblin_variables[i].name.data);
			return NGX_ERROR;
		}

		var->set_handler = goblin_variables[i].set_handler;
		var->get_handler = goblin_variables[i].get_handler;
		var->data = goblin_variables[i].data;
	}

	return NGX_OK;
}

static ngx_int_t goblin_punish_get (ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	uint64_t ucid;
	struct goblin_ruleset_st *ruleset;
	struct goblin_rule_st rule;
	struct sockaddr_in addr;
	char *result;

	if (shared_ruleset==NULL) {
		v->valid = 0;
		v->no_cacheable = 0;
		v->not_found = 1;
		v->data = NULL;
		v->len = 0;
		return NGX_ERROR;
	}

	ruleset = shared_ruleset;

	addr.sin_family = AF_INET;
	if (ngx_module_lianjia_get_real_client_addr(r, (void*)&addr, sizeof(addr))<0) {
		ngx_module_lianjia_get_client_addr(r, (void*)&addr, sizeof(addr));
	}

	ucid = security_lianjia_get_ucid(r);

	rule.ip = ntohl(addr.sin_addr.s_addr);
	rule.ucid = ucid;

	result = ruleset_getpunish(ruleset, &rule);

	v->valid = 1;
	v->no_cacheable = 1;
	v->not_found = 0;
	v->data = (void*)result;
	v->len = strlen(result);

	return NGX_OK;
}
