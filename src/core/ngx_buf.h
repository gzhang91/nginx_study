
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_BUF_H_INCLUDED_
#define _NGX_BUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef void *            ngx_buf_tag_t;

typedef struct ngx_buf_s  ngx_buf_t;

/*
	缓冲结构: 可以指向内存和文件
*/
struct ngx_buf_s {
    u_char          *pos;           // buf的开始指针,这个是会变的,和start不同
    u_char          *last;          // buf的结束指针,这个也是会变的,和end不同
    off_t            file_pos;      // 如果缓冲区指向的是文件,代表文件的开始
    off_t            file_last;     // 如果缓冲区指向的是文件,代表文件的结束

    u_char          *start;         // buf的开始指针,用于释放
    u_char          *end;           // buf的结束指针,用于标识
    ngx_buf_tag_t    tag;           // 未知
    ngx_file_t      *file;          // 文件缓存句柄
    ngx_buf_t       *shadow;


    /* the buf's content could be changed */
    // 缓存会更改
    unsigned         temporary:1;

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    // 在内存中
    unsigned         memory:1;

    /* the buf's content is mmap()ed and must not be changed */
    // 是否mmap
    unsigned         mmap:1;
	// 是否recycled
    unsigned         recycled:1;
    // 是否in_file
    unsigned         in_file:1;
    // 是否flush
    unsigned         flush:1;
    // 是否同步
    unsigned         sync:1;
    // 是否是上次缓存过
    unsigned         last_buf:1;
    // 是否上次在chain中
    unsigned         last_in_chain:1;
	// last_shadow标记
    unsigned         last_shadow:1;
    // 临时文件标记
    unsigned         temp_file:1;

    /* STUB */ int   num;
};


struct ngx_chain_s {
    ngx_buf_t    *buf;
    ngx_chain_t  *next;
};


typedef struct {
    ngx_int_t    num;
    size_t       size;
} ngx_bufs_t;


typedef struct ngx_output_chain_ctx_s  ngx_output_chain_ctx_t;

typedef ngx_int_t (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *in);

typedef void (*ngx_output_chain_aio_pt)(ngx_output_chain_ctx_t *ctx,
    ngx_file_t *file);

struct ngx_output_chain_ctx_s {
	// buf内容
    ngx_buf_t                   *buf;
    // income buf链表
    ngx_chain_t                 *in;
    // free buf链表
    ngx_chain_t                 *free;
    // busy buf链表
    ngx_chain_t                 *busy;
	// sendfile标记
    unsigned                     sendfile:1;
    // directio标记
    unsigned                     directio:1;
    // 没有对齐
    unsigned                     unaligned:1;
    // 在memory中
    unsigned                     need_in_memory:1;
    // 临时的
    unsigned                     need_in_temp:1;
    // aio标记
    unsigned                     aio:1;

#if (NGX_HAVE_FILE_AIO || NGX_COMPAT)
    ngx_output_chain_aio_pt      aio_handler;
#if (NGX_HAVE_AIO_SENDFILE || NGX_COMPAT)
    ssize_t                    (*aio_preload)(ngx_buf_t *file);
#endif
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_int_t                  (*thread_handler)(ngx_thread_task_t *task,
                                                 ngx_file_t *file);
    ngx_thread_task_t           *thread_task;
#endif
	// 对齐大小
    off_t                        alignment;
	// pool内存池
    ngx_pool_t                  *pool;
    // 分配的大小
    ngx_int_t                    allocated;
    // bufs记录结构
    ngx_bufs_t                   bufs;
    // tag标记
    ngx_buf_tag_t                tag;
	// filter输出句柄
    ngx_output_chain_filter_pt   output_filter;
    // filter输出上下文参数
    void                        *filter_ctx;
};


typedef struct {
    ngx_chain_t                 *out;
    ngx_chain_t                **last;
    ngx_connection_t            *connection;
    ngx_pool_t                  *pool;
    off_t                        limit;
} ngx_chain_writer_ctx_t;


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR

// buf是否在memory
#define ngx_buf_in_memory(b)        (b->temporary || b->memory || b->mmap)
// buf是否只在memory,不在文件中
#define ngx_buf_in_memory_only(b)   (ngx_buf_in_memory(b) && !b->in_file)
// 特殊buf
#define ngx_buf_special(b)                                                   \
    ((b->flush || b->last_buf || b->sync)                                    \
     && !ngx_buf_in_memory(b) && !b->in_file)
// sync标记
#define ngx_buf_sync_only(b)                                                 \
    (b->sync                                                                 \
     && !ngx_buf_in_memory(b) && !b->in_file && !b->flush && !b->last_buf)
// 获取buf大小,如果在内存中,使用pos-last;如果在文件中,file_last-file_pos
#define ngx_buf_size(b)                                                      \
    (ngx_buf_in_memory(b) ? (off_t) (b->last - b->pos):                      \
                            (b->file_last - b->file_pos))

ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);


#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))

ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);
#define ngx_free_chain(pool, cl)                                             \
    cl->next = pool->chain;                                                  \
    pool->chain = cl



ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
ngx_int_t ngx_chain_writer(void *ctx, ngx_chain_t *in);

ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in);
ngx_chain_t *ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free);
void ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free,
    ngx_chain_t **busy, ngx_chain_t **out, ngx_buf_tag_t tag);

off_t ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit);

ngx_chain_t *ngx_chain_update_sent(ngx_chain_t *in, off_t sent);

#endif /* _NGX_BUF_H_INCLUDED_ */
