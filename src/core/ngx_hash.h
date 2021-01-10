
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HASH_H_INCLUDED_
#define _NGX_HASH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

/*
	整个hash结构是这样的,
	buckets中存放的就是ngx_hash_elt_t的指针
	如果对于hash冲突的情况,elt存放在elt之后
*/
typedef struct {
    void             *value;   // value
    u_short           len;     // key len
    u_char            name[1]; // key name
} ngx_hash_elt_t;


typedef struct {
	// buckets
    ngx_hash_elt_t  **buckets;
    // 大小
    ngx_uint_t        size;
} ngx_hash_t;


typedef struct {
	// ngx_hash_t句柄
    ngx_hash_t        hash;
    void             *value;
} ngx_hash_wildcard_t;

// hash_key结构体
typedef struct {
	// key字符串
    ngx_str_t         key;
    // key的hash值
    ngx_uint_t        key_hash;
    // key的值
    void             *value;
} ngx_hash_key_t;


typedef ngx_uint_t (*ngx_hash_key_pt) (u_char *data, size_t len);


typedef struct {
	// ngx_hash_t句柄
    ngx_hash_t            hash;
    // 头匹配
    ngx_hash_wildcard_t  *wc_head;
    // 尾匹配
    ngx_hash_wildcard_t  *wc_tail;
} ngx_hash_combined_t;


typedef struct {
	// hash指针
    ngx_hash_t       *hash;
    // hash key函数
    ngx_hash_key_pt   key;
	// 最大size
    ngx_uint_t        max_size;
    // bucket size
    ngx_uint_t        bucket_size;
	// name
    char             *name;
    // 内存池
    ngx_pool_t       *pool;
    // 临时内存池
    ngx_pool_t       *temp_pool;
} ngx_hash_init_t;


#define NGX_HASH_SMALL            1
#define NGX_HASH_LARGE            2

#define NGX_HASH_LARGE_ASIZE      16384
#define NGX_HASH_LARGE_HSIZE      10007

#define NGX_HASH_WILDCARD_KEY     1
#define NGX_HASH_READONLY_KEY     2


typedef struct {
	// hash size
    ngx_uint_t        hsize;
	// 内存池
    ngx_pool_t       *pool;
    // 临时内存池
    ngx_pool_t       *temp_pool;
	// keys数组,ngx_hash_key_t数组
    ngx_array_t       keys;
    // hash key数组,ngx_str_t数组,存储key字符串
    ngx_array_t      *keys_hash;
	// dns head匹配数组, ngx_hash_key_t数组
    ngx_array_t       dns_wc_head;
    // head_hash指针数组, dns_wc_head_hash[i]为ngx_str_t类型
    ngx_array_t      *dns_wc_head_hash;
	// dns tail匹配数组, ngx_hash_key_t数组
    ngx_array_t       dns_wc_tail;
    // tail_hash指针数组, dns_wc_tail_hash[i]为ngx_str_t类型
    ngx_array_t      *dns_wc_tail_hash;
} ngx_hash_keys_arrays_t;


typedef struct {
	// hash值
    ngx_uint_t        hash;
    // key字符串
    ngx_str_t         key;
    // value字符串
    ngx_str_t         value;
    // 小写的key
    u_char           *lowcase_key;
} ngx_table_elt_t;


void *ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len);
void *ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key,
    u_char *name, size_t len);

ngx_int_t ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);
ngx_int_t ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);

#define ngx_hash(key, c)   ((ngx_uint_t) key * 31 + c)
ngx_uint_t ngx_hash_key(u_char *data, size_t len);
ngx_uint_t ngx_hash_key_lc(u_char *data, size_t len);
ngx_uint_t ngx_hash_strlow(u_char *dst, u_char *src, size_t n);


ngx_int_t ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type);
ngx_int_t ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key,
    void *value, ngx_uint_t flags);


#endif /* _NGX_HASH_H_INCLUDED_ */
