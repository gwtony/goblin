#ifndef HASHT_H
#define HASHT_H

#include <stdint.h>
#include "goblin_ruleset.h"

typedef uint32_t hashval_t;

uint32_t murmur_hash(u_char *data, size_t len);
int hasht_init(hasht_t *h, hash_func_t func, cmp_func_t cfunc);
int hasht_delete(hasht_t *h);
int hasht_add_item(hasht_t *h, const uint64_t key, struct goblin_rule_st *rule);
int hasht_find_item(hasht_t *h, const uint64_t key);
int hasht_delete_item(hasht_t *h, const uint64_t key);
int hasht_modify_item(hasht_t *h, const uint64_t key, time_t expire, int punish);

#endif

