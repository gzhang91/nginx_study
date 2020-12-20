
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PALLOC_H_INCLUDED_
#define _NGX_PALLOC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)

#define NGX_DEFAULT_POOL_SIZE    (16 * 1024)

#define NGX_POOL_ALIGNMENT       16
#define NGX_MIN_POOL_SIZE                                                     \
    ngx_align((sizeof(ngx_pool_t) + 2 * sizeof(ngx_pool_large_t)),            \
              NGX_POOL_ALIGNMENT)


typedef void (*ngx_pool_cleanup_pt)(void *data);

typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;

struct ngx_pool_cleanup_s {
    ngx_pool_cleanup_pt   handler;     // 回调函数句柄
    void                 *data;        // 回调函数参数
    ngx_pool_cleanup_t   *next;        // 链接到下一个指针
};


typedef struct ngx_pool_large_s  ngx_pool_large_t;

struct ngx_pool_large_s {
    ngx_pool_large_t     *next;        // 下一个大内存节点指针
    void                 *alloc;       // 大内存节点首指针
};


typedef struct {
    u_char               *last;         // 当前可用内存的指针
    u_char               *end;          // 当前可用内存的结束指针
    ngx_pool_t           *next;         // 下一个内存池节点指针
    ngx_uint_t            failed;       // 当前内存池节点尝试分配内存的失败次数
} ngx_pool_data_t;


struct ngx_pool_s {
    ngx_pool_data_t       d;              // 数据域
    size_t                max;            // 内存池最大尺寸
    ngx_pool_t           *current;        // 当前指向的节点
    ngx_chain_t          *chain;          // 链接在内存池上的chain链表
    ngx_pool_large_t     *large;          // 超过max的大小的内存节点
    ngx_pool_cleanup_t   *cleanup;        // 每个内存池申请的节点对应的清理函数(这是个链表)
    ngx_log_t            *log;            // 日志句柄
};


typedef struct {
    ngx_fd_t              fd;
    u_char               *name;
    ngx_log_t            *log;
} ngx_pool_cleanup_file_t;


ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);
void ngx_destroy_pool(ngx_pool_t *pool);
void ngx_reset_pool(ngx_pool_t *pool);

void *ngx_palloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
void *ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment);
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);


ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *p, size_t size);
void ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd);
void ngx_pool_cleanup_file(void *data);
void ngx_pool_delete_file(void *data);

/*
	自定义内存池的打印函数
*/
void ngx_pool_show_info(ngx_pool_t *p);


#endif /* _NGX_PALLOC_H_INCLUDED_ */
