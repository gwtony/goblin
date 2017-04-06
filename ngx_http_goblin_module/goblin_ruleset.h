#ifndef GOBLIN_RULESET_H
#define GOBLIN_RULESET_H

#include <stdint.h>
#include <time.h>
#include <ngx_core.h>

#include "lianjia_support.h"

#define PUNISH_SIZE (16+1)
#define PUNISH_ARG_SIZE (16+1)

enum {
	CAPTCHA = 1,
	LOGIN = 2,
	FORBIDDEN = 3
};

#define DEFAULT_PUNISH "UNKNOWN"
#define CAPTCHA_STR "captcha"
#define LOGIN_STR "login"
#define FORBIDDEN_STR "forbidden"

#define	BUCKET_DEFAULT_SIZE	65535
typedef uint32_t (* hash_func_t) (u_char *data, size_t size);
typedef int (* cmp_func_t) (uint64_t key, void *rule);

struct goblin_rule_st {
	uint32_t ip;		// IPv4 address as an unsigned int, in HOST byte order.
	
	uint64_t ucid;
	time_t expire; //expire timestamp in second
	int punish; //punish index
	
	int index;
	struct goblin_rule_st *prev, *next; //hash table pointer
	struct goblin_rule_st *lnext; //reuse list pointer
};

struct bucket_st {
	pthread_rwlockattr_t attr;
	pthread_rwlock_t rwlock;
	struct goblin_rule_st *base;
	int nr_nodes;
};

typedef struct hasht_t {
	pthread_rwlockattr_t attr;
	pthread_rwlock_t rwlock;
	hash_func_t hash_func;
	cmp_func_t cmp_func;
	int nr_nodes, nr_buckets;
	struct bucket_st bucket[BUCKET_DEFAULT_SIZE];
} hasht_t;

#define RULESET_SIZE	1500000
//free 500 
#define FREE_RULESET_SIZE	(RULESET_SIZE * 0.0005)
struct goblin_ruleset_st {
	pthread_mutexattr_t attr;
	pthread_mutex_t lock;
	struct goblin_rule_st rules[RULESET_SIZE];  // Array of struct goblin_rule_st
	int rule_next;
	int free_pos;
	int nr_rules;
	hasht_t ucid_htable;
	hasht_t ip_htable;
	struct goblin_rule_st *free;
};

int rule_is_expired(struct goblin_rule_st *rule);
void rule_free(struct goblin_ruleset_st *ruleset, int i);
int ruleset_get_free(struct goblin_ruleset_st *ruleset);
void ruleset_init(struct goblin_ruleset_st *p);
int ruleset_rule_search(struct goblin_ruleset_st *ruleset, struct goblin_rule_st *req);
int ruleset_rules_atomic_add(struct goblin_ruleset_st *ruleset, struct goblin_rule_st *rule);
void ruleset_rule_del(struct goblin_ruleset_st *ruleset, int n);
void ruleset_rule_del_unlocked(struct goblin_ruleset_st *ruleset, int n);
int ruleset_rule_del_ip(struct goblin_ruleset_st *ruleset, int32_t ip);
int ruleset_rule_del_ucid(struct goblin_ruleset_st *ruleset, int64_t ucid);
int ruleset_rules_atomic_del(struct goblin_ruleset_st *ruleset, struct goblin_rule_st *rule);
char * ruleset_getpunish(struct goblin_ruleset_st *ruleset, struct goblin_rule_st *rule);

#endif

