#include <stdio.h>
#include <pthread.h>
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "goblin_ruleset.h"
#include "goblin_hash_table.h"

static char *punisharr[4] = {"UNKNOWN", "captcha", "login", "forbidden"};

int rule_ip_match(uint64_t key, void *rule1)
{
	struct goblin_rule_st *r1 = rule1;
	return key == r1->ip;
}
int rule_ucid_match(uint64_t key, void *rule1)
{
	struct goblin_rule_st *r1 = rule1;
	return key == r1->ucid;
}

int rule_is_expired(struct goblin_rule_st *rule)
{
	return rule->expire < time(NULL);
}

void rule_free(struct goblin_ruleset_st *ruleset, int i)
{
	ruleset->rules[i].ip = 0;
	ruleset->rules[i].ucid = 0;
	ruleset->rules[i].punish = 0;

	//append to free list
	ruleset->rules[i].lnext = ruleset->free;
	ruleset->free = &ruleset->rules[i];
}

int ruleset_get_free(struct goblin_ruleset_st *ruleset)
{
	int index;

	if (ruleset->free) {
		index = ruleset->free->index;
		ruleset->free = ruleset->free->lnext;
		return index;
	}

	if (ruleset->rule_next >= RULESET_SIZE) {
		return -1;
	}

	index = ruleset->rule_next;
	ruleset->rule_next++;

	return index;
}

void ruleset_init(struct goblin_ruleset_st *p)
{
#ifdef DEBUG
	int i;
	struct goblin_rule_st tmp;
#endif
	pthread_mutexattr_init(&p->attr);
	pthread_mutexattr_setpshared(&p->attr, PTHREAD_PROCESS_SHARED);
	pthread_mutex_init(&p->lock, &p->attr);

	memset(p->rules, 0, sizeof(struct goblin_rule_st) * RULESET_SIZE);

	p->free_pos = 0;
	p->rule_next = 0;
	p->nr_rules = 0;
	hasht_init(&p->ucid_htable, NULL, rule_ucid_match);
	hasht_init(&p->ip_htable, NULL, rule_ip_match);
	p->free = NULL;

#ifdef DEBUG
#define TEST_RULE_NUM 1000000
	fprintf(stderr, "debug data init begin at %llu\n", time(NULL));
	for (i = 1; i < TEST_RULE_NUM + 1; i++) {
		tmp.ip = 0;
		tmp.ucid = i;
		tmp.expire = time(NULL) + 300; //
		tmp.punish = CAPTCHA;
		ruleset_rules_atomic_add(p, &tmp);
	}
	fprintf(stderr, "debug data init done at %llu\n", time(NULL));
#endif
}

//return index of pusharr
int ruleset_rule_search(struct goblin_ruleset_st *ruleset, struct goblin_rule_st *req)
{
	int ret;

	if (req->ucid > 0) {
		ret = hasht_find_item(&ruleset->ucid_htable, req->ucid);
		if (ret >= 0) {	// Got a result 
			if (ruleset->rules[ret].expire < time(NULL)) {	// But expired.
				ruleset_rule_del(ruleset, ret);
				return 0;
			}
			return ruleset->rules[ret].punish;
		}
		return 0;
	}
	ret = hasht_find_item(&ruleset->ip_htable, req->ip);
	if (ret >= 0) {	// Got a result 
		if (ruleset->rules[ret].expire < time(NULL)) {	// But expired.
			ruleset_rule_del(ruleset, ret);
			return 0;
		}
		return ruleset->rules[ret].punish;
	}

	return 0;

}

int ruleset_rules_atomic_add(struct goblin_ruleset_st *ruleset, struct goblin_rule_st *rule)
{
	int i, ret = 0;
	int pos;

	if (rule == NULL) {
		return -1;
	}

	if (rule->expire < time(NULL)) {
		//return some value
		return -3;
	}

	pthread_mutex_lock(&ruleset->lock);

	if (rule->ip != 0 && rule->ucid == 0) {
		ret = hasht_find_item(&ruleset->ip_htable, rule->ip);
		if (ret >= 0) {
			hasht_modify_item(&ruleset->ip_htable, rule->ip, rule->expire, rule->punish);
			pthread_mutex_unlock(&ruleset->lock);
			return 0;
		}
	} else if (rule->ip == 0 && rule->ucid != 0) {
		ret = hasht_find_item(&ruleset->ucid_htable, rule->ucid);
		if (ret >= 0) {
			hasht_modify_item(&ruleset->ucid_htable, rule->ucid, rule->expire, rule->punish);
			pthread_mutex_unlock(&ruleset->lock);
			return 0;
		}
	}

	if (ruleset->nr_rules >= (RULESET_SIZE * 0.9)) {
		//check FREE_RULESET_SIZE rules each travel
		int count = 0;
		//int free = 0;
		for (i = ruleset->free_pos; i < ruleset->rule_next; ++i) {
			count++;
			if ((ruleset->rules[i].punish > 0) && (ruleset->rules[i].expire < time(NULL))) {
				ruleset_rule_del_unlocked(ruleset, i);
				//free++;
			}
			if (count >= FREE_RULESET_SIZE) {
				break;
			}
		}
		//fprintf(stderr, "in add free %d rules\n", free);
		ruleset->free_pos += count;
		if (ruleset->free_pos >= ruleset->rule_next) {
			ruleset->free_pos -= ruleset->rule_next;
		}
	}

	pos = ruleset_get_free(ruleset);
	if (pos < 0) {
		pthread_mutex_unlock(&ruleset->lock);
		return -1;
	}

	ruleset->rules[pos].ip = rule->ip;
	ruleset->rules[pos].prev = NULL;
	ruleset->rules[pos].next = NULL;
	ruleset->rules[pos].lnext = NULL;
	ruleset->rules[pos].ucid = rule->ucid;
	ruleset->rules[pos].expire = rule->expire;
	ruleset->rules[pos].index = pos;
	ruleset->rules[pos].punish = rule->punish;

	if (rule->ip != 0 && rule->ucid == 0) {
		hasht_add_item(&ruleset->ip_htable, rule->ip, &ruleset->rules[pos]);
	} else if (rule->ip == 0 && rule->ucid != 0) {
		hasht_add_item(&ruleset->ucid_htable, rule->ucid, &ruleset->rules[pos]);
	}

	ruleset->nr_rules++;
	//fprintf(stderr, "rule add nr_rules is %d\n", ruleset->nr_rules);
	pthread_mutex_unlock(&ruleset->lock);

	return 0;
}

void ruleset_rule_del(struct goblin_ruleset_st *ruleset, int n)
{
	int ret = -1;
	pthread_mutex_lock(&ruleset->lock);
	if (ruleset->rules[n].ip > 0) {
		ret = hasht_delete_item(&ruleset->ip_htable, ruleset->rules[n].ip);
	}
	if (ruleset->rules[n].ucid > 0) {
		ret = hasht_delete_item(&ruleset->ucid_htable, ruleset->rules[n].ucid);
	}
	if (ret >= 0) {
		rule_free(ruleset, n);
		ruleset->nr_rules--;
	}
	pthread_mutex_unlock(&ruleset->lock);
}

void ruleset_rule_del_unlocked(struct goblin_ruleset_st *ruleset, int n)
{
	int ret = -1;
	if (ruleset->rules[n].ip > 0) {
		ret = hasht_delete_item(&ruleset->ip_htable, ruleset->rules[n].ip);
	}
	if (ruleset->rules[n].ucid > 0) {
		ret = hasht_delete_item(&ruleset->ucid_htable, ruleset->rules[n].ucid);
	}
	if (ret >= 0) {
		rule_free(ruleset, n);
		ruleset->nr_rules--;
	}
}

int ruleset_rule_del_ip(struct goblin_ruleset_st *ruleset, int32_t ip)
{
	int idx;
	idx = hasht_delete_item(&ruleset->ip_htable, ip);
	if (idx >= 0) {
		rule_free(ruleset, idx);
		return 0;
	}
	return -1;
}

int ruleset_rule_del_ucid(struct goblin_ruleset_st *ruleset, int64_t ucid)
{
	int idx;
	idx = hasht_delete_item(&ruleset->ucid_htable, ucid);
	if (idx >= 0) {
		rule_free(ruleset, idx);
		return 0;
	}
	return -1;
}

int ruleset_rules_atomic_del(struct goblin_ruleset_st *ruleset, struct goblin_rule_st *rule)
{
	int ret = -1;

	pthread_mutex_lock(&ruleset->lock);
	if (rule->ip > 0) {
		ret = ruleset_rule_del_ip(ruleset, rule->ip);
	} else if (rule->ucid > 0 ) {
		ret = ruleset_rule_del_ucid(ruleset, rule->ucid);
	}
	if (ret >= 0) {
		ruleset->nr_rules--;
	}
	pthread_mutex_unlock(&ruleset->lock);

	return ret;
}

char * ruleset_getpunish(struct goblin_ruleset_st *ruleset, struct goblin_rule_st *rule)
{
	int ret;

	ret = ruleset_rule_search(ruleset, rule);
	
	return punisharr[ret];
}

