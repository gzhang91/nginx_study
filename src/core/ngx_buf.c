
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

/*
	在内存池中创建一个ngx_buf_t结构,大小为size
*/
ngx_buf_t *
ngx_create_temp_buf(ngx_pool_t *pool, size_t size)
{
    ngx_buf_t *b;
	// 在内存池中生成一个ngx_buf_t结构体
    b = ngx_calloc_buf(pool);
    if (b == NULL) {
        return NULL;
    }
	// 申请size的内存
    b->start = ngx_palloc(pool, size);
    if (b->start == NULL) {
        return NULL;
    }

    /*
     * set by ngx_calloc_buf():
     *
     *     b->file_pos = 0;
     *     b->file_last = 0;
     *     b->file = NULL;
     *     b->shadow = NULL;
     *     b->tag = 0;
     *     and flags
     */

    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + size;
    // 临时temporary标记
    b->temporary = 1;

    return b;
}

/*
	从pool中获取一个chain结构体,如果pool->chain中存在了,就不需要重新生成了;
	如果pool->chain不存在,就需要在pool中生成一个chain结构体
*/
ngx_chain_t *
ngx_alloc_chain_link(ngx_pool_t *pool)
{
    ngx_chain_t  *cl;
	// pool中的chain标记
    cl = pool->chain;
	// 如果cl已经存在,pool->chain指向下一个地址
    if (cl) {
        pool->chain = cl->next;
        return cl;
    }
	// 如果cl不存在,重新申请ngx_chain_t结构
    cl = ngx_palloc(pool, sizeof(ngx_chain_t));
    if (cl == NULL) {
        return NULL;
    }

    return cl;
}

/*
	将size个bufs连成一条链
*/
ngx_chain_t *
ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs)
{
    u_char       *p;
    ngx_int_t     i;
    ngx_buf_t    *b;
    ngx_chain_t  *chain, *cl, **ll;
	// 生成num * size字节内存大小
    p = ngx_palloc(pool, bufs->num * bufs->size);
    if (p == NULL) {
        return NULL;
    }
	// 局部变量chain内存地址
    ll = &chain;

    for (i = 0; i < bufs->num; i++) {
		// 申请一个ngx_buf_t结构体
        b = ngx_calloc_buf(pool);
        if (b == NULL) {
            return NULL;
        }

        /*
         * set by ngx_calloc_buf():
         *
         *     b->file_pos = 0;
         *     b->file_last = 0;
         *     b->file = NULL;
         *     b->shadow = NULL;
         *     b->tag = 0;
         *     and flags
         *
         */
		// 每个buf指向p的一个size大小的内存
        b->pos = p;
        b->last = p;
        b->temporary = 1;

        b->start = p;
        p += bufs->size;
        b->end = p;
		// 使用chain中的buf指向b
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NULL;
        }
		// 将ll的chain连成一条链
        cl->buf = b;
        *ll = cl;
        ll = &cl->next;
    }

    *ll = NULL;

    return chain;
}

/*
	将in中的buf连缀到chain中
*/
ngx_int_t
ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain, ngx_chain_t *in)
{
    ngx_chain_t  *cl, **ll;

    ll = chain;

	// 循环到*chain的结尾,将ll指向cl->next的地址
    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    while (in) {
    	// 在内存池中申请一个ngx_chain_t结构体
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            *ll = NULL;
            return NGX_ERROR;
        }

        cl->buf = in->buf;
        // 将之前存储的cl->next的地址指向创建的cl
        *ll = cl;
        // ll存储cl->next的地址
        ll = &cl->next;
        // 继续循环ngx_chain_t的下一个节点
        in = in->next;
    }

    *ll = NULL;

    return NGX_OK;
}

/*
	从free中获取空闲的buf,如果free为空,就重新在内存池中申请一个结构
*/
ngx_chain_t *
ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free)
{
    ngx_chain_t  *cl;
	// 如果*free有chain,就从free中获取
    if (*free) {
        cl = *free;
        *free = cl->next;
        cl->next = NULL;
        return cl;
    }
	// 申请chain结构体
    cl = ngx_alloc_chain_link(p);
    if (cl == NULL) {
        return NULL;
    }
	// 申请buf结构体
    cl->buf = ngx_calloc_buf(p);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    return cl;
}

/*
	功能:将busy和out追加到free链表上
	细节:将out先连缀到busy链表上,之后从busy链表进行处理,将busy链表节点都连缀到free链表中
*/
void
ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free, ngx_chain_t **busy,
    ngx_chain_t **out, ngx_buf_tag_t tag)
{
    ngx_chain_t  *cl;
	// 如果*out不为空
    if (*out) {
    	// 如果*busy不为空,将*busy指向*out
        if (*busy == NULL) {
            *busy = *out;

        } else {
        // 否则,将*out缀接到*busy的尾部
            for (cl = *busy; cl->next; cl = cl->next) { /* void */ }

            cl->next = *out;
        }

        *out = NULL;
    }

    while (*busy) {
        cl = *busy;
		// 如果buf_size==0,直接不处理
        if (ngx_buf_size(cl->buf) != 0) {
            break;
        }
		// 如果buf中的tag和输入的tag不一致就不处理
        if (cl->buf->tag != tag) {
            *busy = cl->next;
            ngx_free_chain(p, cl);
            continue;
        }

        cl->buf->pos = cl->buf->start;
        cl->buf->last = cl->buf->start;
		// *busy指向下一个
        *busy = cl->next;
        cl->next = *free;
        // 将cl连缀到free链表上
        *free = cl;
    }
}

/*
	从文件中获取<limit大小内容
*/
off_t
ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit)
{
    off_t         total, size, aligned, fprev;
    ngx_fd_t      fd;
    ngx_chain_t  *cl;

    total = 0;

    cl = *in;
    fd = cl->buf->file->fd;

    do {
    	// 获取文件缓存大小
        size = cl->buf->file_last - cl->buf->file_pos;

        if (size > limit - total) {
            size = limit - total;
			// 和ngx_pagesize对齐
            aligned = (cl->buf->file_pos + size + ngx_pagesize - 1)
                       & ~((off_t) ngx_pagesize - 1);

            if (aligned <= cl->buf->file_last) {
                size = aligned - cl->buf->file_pos;
            }

            total += size;
            break;
        }

        total += size;
        fprev = cl->buf->file_pos + size;
        cl = cl->next;

    } while (cl
             && cl->buf->in_file
             && total < limit
             && fd == cl->buf->file->fd
             && fprev == cl->buf->file_pos);

    *in = cl;

    return total;
}

/*
	从in中找到大于等于sent的chain 的buf
*/
ngx_chain_t *
ngx_chain_update_sent(ngx_chain_t *in, off_t sent)
{
    off_t  size;

    for ( /* void */ ; in; in = in->next) {

        if (ngx_buf_special(in->buf)) {
            continue;
        }

        if (sent == 0) {
            break;
        }

        size = ngx_buf_size(in->buf);

        if (sent >= size) {
            sent -= size;

            if (ngx_buf_in_memory(in->buf)) {
                in->buf->pos = in->buf->last;
            }

            if (in->buf->in_file) {
                in->buf->file_pos = in->buf->file_last;
            }

            continue;
        }

        if (ngx_buf_in_memory(in->buf)) {
            in->buf->pos += (size_t) sent;
        }

        if (in->buf->in_file) {
            in->buf->file_pos += sent;
        }

        break;
    }

    return in;
}
