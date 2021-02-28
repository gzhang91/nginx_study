
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SLAB_H_INCLUDED_
#define _NGX_SLAB_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_slab_page_s  ngx_slab_page_t;

struct ngx_slab_page_s {
	// slab page
    uintptr_t         slab;
    // next下一个节点
    ngx_slab_page_t  *next;
    // prev之前节点
    uintptr_t         prev;
};


typedef struct {
	// 总数
    ngx_uint_t        total;
    // 使用数
    ngx_uint_t        used;
	// 请求数
    ngx_uint_t        reqs;
    // 失败数
    ngx_uint_t        fails;
} ngx_slab_stat_t;


typedef struct {
	// lock 句柄
    ngx_shmtx_sh_t    lock;
	// 最小的大小
    size_t            min_size;
    // 增长值
    size_t            min_shift;
	// pages列表
    ngx_slab_page_t  *pages;
    // 尾指针
    ngx_slab_page_t  *last;
    // 空闲指针
    ngx_slab_page_t   free;
	// 状态指针
    ngx_slab_stat_t  *stats;
    // free的次数
    ngx_uint_t        pfree;
	// start指针
    u_char           *start;
    // end指针
    u_char           *end;
	// sem句柄
    ngx_shmtx_t       mutex;
	// 日志上下文
    u_char           *log_ctx;
    // 零标记
    u_char            zero;
	// nomem标记
    unsigned          log_nomem:1;
	// 参数
    void             *data;
    // 地址
    void             *addr;
} ngx_slab_pool_t;


void ngx_slab_sizes_init(void);
void ngx_slab_init(ngx_slab_pool_t *pool);
void *ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_calloc(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_calloc_locked(ngx_slab_pool_t *pool, size_t size);
void ngx_slab_free(ngx_slab_pool_t *pool, void *p);
void ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p);


#endif /* _NGX_SLAB_H_INCLUDED_ */
