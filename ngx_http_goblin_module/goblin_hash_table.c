#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>

#include "goblin_hash_table.h"

uint32_t
murmur_hash(u_char *data, size_t len)
{
    uint32_t  h, k;

    h = 0 ^ len;

    while (len >= 4) {
        k  = data[0];
        k |= data[1] << 8;
        k |= data[2] << 16;
        k |= data[3] << 24;

        k *= 0x5bd1e995;
        k ^= k >> 24;
        k *= 0x5bd1e995;

        h *= 0x5bd1e995;
        h ^= k;

        data += 4;
        len -= 4;
    }

    switch (len) {
    case 3:
        h ^= data[2] << 16;
    case 2:
        h ^= data[1] << 8;
    case 1:
        h ^= data[0];
        h *= 0x5bd1e995;
    }

    h ^= h >> 13;
    h *= 0x5bd1e995;
    h ^= h >> 15;

    return h;
}

int hasht_init(hasht_t *h, hash_func_t func, cmp_func_t cfunc)
{
	int i;
	if (h == NULL) {
		return -1;
	}

	if (func == NULL) {
		h->hash_func = &murmur_hash;
	} else {
		h->hash_func = func;
	}

	if (cfunc == NULL) {
		return -1;
	}
	h->cmp_func = cfunc;

	pthread_rwlockattr_init(&h->attr);
	pthread_rwlockattr_setpshared(&h->attr, PTHREAD_PROCESS_SHARED);
	pthread_rwlock_init(&h->rwlock, &h->attr);

	h->nr_nodes = 0;
	h->nr_buckets = BUCKET_DEFAULT_SIZE;

	for (i = 0; i < h->nr_buckets; ++i) {
		h->bucket[i].base = NULL;
		h->bucket[i].nr_nodes = 0;

		pthread_rwlockattr_init(&h->bucket[i].attr);
		pthread_rwlockattr_setpshared(&h->bucket[i].attr, PTHREAD_PROCESS_SHARED);
		pthread_rwlock_init(&h->bucket[i].rwlock, &h->bucket[i].attr);
	}

	return 0;
}

int hasht_delete(hasht_t *h)
{
	int i;
	for (i = 0; i < h->nr_buckets; ++i) {
		pthread_rwlockattr_destroy(&h->bucket[i].attr);
		pthread_rwlock_destroy(&h->bucket[i].rwlock);
	}

	pthread_rwlockattr_destroy(&h->attr);
	pthread_rwlock_destroy(&h->rwlock);
	return 0;
}

int hasht_add_item(hasht_t *h, const uint64_t key, struct goblin_rule_st *rule)
{
	hashval_t hash;

	hash = murmur_hash((u_char *)&key, sizeof(uint64_t)) % h->nr_buckets;

	pthread_rwlock_wrlock(&h->bucket[hash].rwlock);
	if (!h->bucket[hash].base) {
		h->bucket[hash].base = rule;
	} else {
		rule->next = h->bucket[hash].base;	
		h->bucket[hash].base->prev = rule;
		h->bucket[hash].base = rule;
	}

	h->bucket[hash].nr_nodes++;
	pthread_rwlock_unlock(&h->bucket[hash].rwlock);
	
	pthread_rwlock_wrlock(&h->rwlock);
	h->nr_nodes++;
	pthread_rwlock_unlock(&h->rwlock);
	
	return 0;
}

int hasht_find_item(hasht_t *h, const uint64_t key)
{
	hashval_t hash;
	struct goblin_rule_st *rule;

	hash = murmur_hash((u_char *)&key, sizeof(uint64_t)) % h->nr_buckets;

	pthread_rwlock_rdlock(&h->bucket[hash].rwlock);
	rule = h->bucket[hash].base; 
	while (rule != NULL) {
		if (h->cmp_func(key, rule)) {
			//match
			pthread_rwlock_unlock(&h->bucket[hash].rwlock);
			return rule->index;
		}
		rule = rule->next;
	}

	pthread_rwlock_unlock(&h->bucket[hash].rwlock);
	return -1;
}

int hasht_delete_item(hasht_t *h, const uint64_t key)
{
	int index;
	hashval_t hash;
	struct goblin_rule_st *rule;
	
	hash = murmur_hash((u_char *)&key, sizeof(uint64_t)) % h->nr_buckets;

	pthread_rwlock_wrlock(&h->bucket[hash].rwlock);
	rule = h->bucket[hash].base; 
	while (rule != NULL) {
		if (h->cmp_func(key, rule)) {
			//match
			index = rule->index;
			if (rule->prev) {
				rule->prev->next = rule->next;
			} else {
				h->bucket[hash].base = rule->next;
			}
			if (rule->next) {
				rule->next->prev = rule->prev;
			}
			h->bucket[hash].nr_nodes--;
			pthread_rwlock_unlock(&h->bucket[hash].rwlock);

			pthread_rwlock_wrlock(&h->rwlock);
			h->nr_nodes--;
			pthread_rwlock_unlock(&h->rwlock);
			return index;
		}
		rule = rule->next;
	}

	pthread_rwlock_unlock(&h->bucket[hash].rwlock);

	return -1;
}

int hasht_modify_item(hasht_t *h, const uint64_t key, time_t expire, int punish)
{
	hashval_t hash;
	struct goblin_rule_st *rule;
	
	hash = murmur_hash((u_char *)&key, sizeof(uint64_t)) % h->nr_buckets;

	pthread_rwlock_wrlock(&h->bucket[hash].rwlock);
	rule = h->bucket[hash].base; 
	while (rule != NULL) {
		if (h->cmp_func(key, rule)) {
			//match
			rule->expire = expire;
			rule->punish = punish;
			pthread_rwlock_unlock(&h->bucket[hash].rwlock);
			return rule->index;
		}
		rule = rule->next;
	}

	pthread_rwlock_unlock(&h->bucket[hash].rwlock);
	return -1;	
}
