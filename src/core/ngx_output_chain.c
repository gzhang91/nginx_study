
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if 0
#define NGX_SENDFILE_LIMIT  4096
#endif

/*
 * When DIRECTIO is enabled FreeBSD, Solaris, and MacOSX read directly
 * to an application memory from a device if parameters are aligned
 * to device sector boundary (512 bytes).  They fallback to usual read
 * operation if the parameters are not aligned.
 * Linux allows DIRECTIO only if the parameters are aligned to a filesystem
 * sector boundary, otherwise it returns EINVAL.  The sector size is
 * usually 512 bytes, however, on XFS it may be 4096 bytes.
 */

#define NGX_NONE            1


static ngx_inline ngx_int_t
    ngx_output_chain_as_is(ngx_output_chain_ctx_t *ctx, ngx_buf_t *buf);
#if (NGX_HAVE_AIO_SENDFILE)
static ngx_int_t ngx_output_chain_aio_setup(ngx_output_chain_ctx_t *ctx,
    ngx_file_t *file);
#endif
static ngx_int_t ngx_output_chain_add_copy(ngx_pool_t *pool,
    ngx_chain_t **chain, ngx_chain_t *in);
static ngx_int_t ngx_output_chain_align_file_buf(ngx_output_chain_ctx_t *ctx,
    off_t bsize);
static ngx_int_t ngx_output_chain_get_buf(ngx_output_chain_ctx_t *ctx,
    off_t bsize);
static ngx_int_t ngx_output_chain_copy_buf(ngx_output_chain_ctx_t *ctx);


ngx_int_t
ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in)
{
    off_t         bsize;
    ngx_int_t     rc, last;
    ngx_chain_t  *cl, *out, **last_out;
	// 如果ctx(可以理解为上下文结构体)中的in链表为空且busy链表也为空
    if (ctx->in == NULL && ctx->busy == NULL
#if (NGX_HAVE_FILE_AIO || NGX_THREADS)
        && !ctx->aio
#endif
       )
    {
        /*
         * the short path for the case when the ctx->in and ctx->busy chains
         * are empty, the incoming chain is empty too or has the single buf
         * that does not require the copy
         */
		// in链表为空,说明没有缓存存在直接调用output_filter
        if (in == NULL) {
            return ctx->output_filter(ctx->filter_ctx, in);
        }
		// in不为空,不存在next
        if (in->next == NULL
#if (NGX_SENDFILE_LIMIT)
		// 如果 !(不) 存在buf在文件中且存在sendfile_limit>NGX_SENDFILE_LIMIT
            && !(in->buf->in_file && in->buf->file_last > NGX_SENDFILE_LIMIT)
#endif	// 查看缓存是否能处理
            && ngx_output_chain_as_is(ctx, in->buf))
        {	// 调用output_filter处理
            return ctx->output_filter(ctx->filter_ctx, in);
        }
    }

    /* add the incoming buf to the chain ctx->in */
	// 如果in存在
    if (in) {
    	// 直接将in加入到ctx->in中
        if (ngx_output_chain_add_copy(ctx->pool, &ctx->in, in) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    out = NULL;
    last_out = &out;
    last = NGX_NONE;

    for ( ;; ) {

#if (NGX_HAVE_FILE_AIO || NGX_THREADS)
        if (ctx->aio) {
            return NGX_AGAIN;
        }
#endif
		// 循环处理ctx->in链表
        while (ctx->in) {

            /*
             * cycle while there are the ctx->in bufs
             * and there are the free output bufs to copy in
             */
			// 获取ctx->in这个节点的buf大小
            bsize = ngx_buf_size(ctx->in->buf);
			// 如果buf size为0,而且非special buf,直接返回错误
            if (bsize == 0 && !ngx_buf_special(ctx->in->buf)) {

                ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
                              "zero size buf in output "
                              "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                              ctx->in->buf->temporary,
                              ctx->in->buf->recycled,
                              ctx->in->buf->in_file,
                              ctx->in->buf->start,
                              ctx->in->buf->pos,
                              ctx->in->buf->last,
                              ctx->in->buf->file,
                              ctx->in->buf->file_pos,
                              ctx->in->buf->file_last);

                ngx_debug_point();
				// 处理下一个链表节点
                ctx->in = ctx->in->next;

                continue;
            }
			// bsize小于0,扯淡不
            if (bsize < 0) {

                ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
                              "negative size buf in output "
                              "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                              ctx->in->buf->temporary,
                              ctx->in->buf->recycled,
                              ctx->in->buf->in_file,
                              ctx->in->buf->start,
                              ctx->in->buf->pos,
                              ctx->in->buf->last,
                              ctx->in->buf->file,
                              ctx->in->buf->file_pos,
                              ctx->in->buf->file_last);

                ngx_debug_point();

                return NGX_ERROR;
            }

			// bsize > 0
            
			// 判断是能够处理的buf
            if (ngx_output_chain_as_is(ctx, ctx->in->buf)) {

                /* move the chain link to the output chain */
				// 取出这个节点,由cl指针指向它
                cl = ctx->in;
                ctx->in = cl->next;

                *last_out = cl;
                last_out = &cl->next;
                cl->next = NULL;

                continue;
            }
			// ctx->buf为空
            if (ctx->buf == NULL) {
				// 将ctx中的buf按bsize对齐
                rc = ngx_output_chain_align_file_buf(ctx, bsize);

                if (rc == NGX_ERROR) {
                    return NGX_ERROR;
                }
				// rc == NGX_DECLINED
                if (rc != NGX_OK) {

                    if (ctx->free) {

                        /* get the free buf */
						// 获取free buf
                        cl = ctx->free;
                        ctx->buf = cl->buf;
                        ctx->free = cl->next;
						// 加入到free chain中
                        ngx_free_chain(ctx->pool, cl);

                    } else if (out || ctx->allocated == ctx->bufs.num) {
					// allocated == bufs.num
                        break;

                    } else if (ngx_output_chain_get_buf(ctx, bsize) != NGX_OK) {
                    // 获取bsize大小的buf
                        return NGX_ERROR;
                    }
                }
            }
			// 拷贝数据
            rc = ngx_output_chain_copy_buf(ctx);

            if (rc == NGX_ERROR) {
                return rc;
            }

            if (rc == NGX_AGAIN) {
                if (out) {
                    break;
                }

                return rc;
            }

            /* delete the completed buf from the ctx->in chain */
			// 获取in->buf==0,将in移动到下一个链表
            if (ngx_buf_size(ctx->in->buf) == 0) {
                ctx->in = ctx->in->next;
            }
			// 从内存池中申请一个ngx_chain_t结构体对象
            cl = ngx_alloc_chain_link(ctx->pool);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            cl->buf = ctx->buf;
            cl->next = NULL;
            *last_out = cl;
            last_out = &cl->next;
            ctx->buf = NULL;
        }

        if (out == NULL && last != NGX_NONE) {

            if (ctx->in) {
                return NGX_AGAIN;
            }

            return last;
        }
		// 调用output_filter
        last = ctx->output_filter(ctx->filter_ctx, out);

        if (last == NGX_ERROR || last == NGX_DONE) {
            return last;
        }
		// 更新busy,out链表
        ngx_chain_update_chains(ctx->pool, &ctx->free, &ctx->busy, &out,
                                ctx->tag);
        last_out = &out;
    }
}

/*
	检测是否是可以处理的缓存,返回值0代表不处理,1代表可以处理,是正常的缓存
*/
static ngx_inline ngx_int_t
ngx_output_chain_as_is(ngx_output_chain_ctx_t *ctx, ngx_buf_t *buf)
{
    ngx_uint_t  sendfile;
	// 特殊buf不处理
    if (ngx_buf_special(buf)) {
        return 1;
    }

#if (NGX_THREADS)
    if (buf->in_file) {
        buf->file->thread_handler = ctx->thread_handler;
        buf->file->thread_ctx = ctx->filter_ctx;
    }
#endif
	// buf在文件中,且支持directio,不可能有缓存,不处理
    if (buf->in_file && buf->file->directio) {
        return 0;
    }

    sendfile = ctx->sendfile;

#if (NGX_SENDFILE_LIMIT)
	// buf在文件中,且当前已缓冲的数据量大于了NGX_SENDFILE_LIMIT
    if (buf->in_file && buf->file_pos >= NGX_SENDFILE_LIMIT) {
    	// 重置sendfile
        sendfile = 0;
    }

#endif
	
    if (!sendfile) { // sendfile == 0
		// 没有在内存中,直接返回
        if (!ngx_buf_in_memory(buf)) {
            return 0;
        }
		// 设置in_file=0
        buf->in_file = 0;
    }

#if (NGX_HAVE_AIO_SENDFILE)
    if (ctx->aio_preload && buf->in_file) {
        (void) ngx_output_chain_aio_setup(ctx, buf->file);
    }
#endif
	// 需要在内存中,但是没有在内存中,直接返回0
    if (ctx->need_in_memory && !ngx_buf_in_memory(buf)) {
        return 0;
    }
	// 需要在temp中,但是memory和mmap标记存在,直接返回0
    if (ctx->need_in_temp && (buf->memory || buf->mmap)) {
        return 0;
    }

    return 1;
}


#if (NGX_HAVE_AIO_SENDFILE)

static ngx_int_t
ngx_output_chain_aio_setup(ngx_output_chain_ctx_t *ctx, ngx_file_t *file)
{
    ngx_event_aio_t  *aio;

    if (file->aio == NULL && ngx_file_aio_init(file, ctx->pool) != NGX_OK) {
        return NGX_ERROR;
    }

    aio = file->aio;

    aio->data = ctx->filter_ctx;
    aio->preload_handler = ctx->aio_preload;

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_output_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in)
{
    ngx_chain_t  *cl, **ll;
#if (NGX_SENDFILE_LIMIT)
    ngx_buf_t    *b, *buf;
#endif

    ll = chain;
	// 将ll指向chain的尾部
    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }
	// 如果in存在
    while (in) {
		// 先获取一个ngx_chain_t结构体对象
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

#if (NGX_SENDFILE_LIMIT)

        buf = in->buf;
		// 如果buf是在in_file中,而且file_pos<NGX_SENDFILE_LIMIT<file_last
        if (buf->in_file
            && buf->file_pos < NGX_SENDFILE_LIMIT
            && buf->file_last > NGX_SENDFILE_LIMIT)
        {
            /* split a file buf on two bufs by the sendfile limit */
			// 申请一个ngx_buf_t结构体对象
            b = ngx_calloc_buf(pool);
            if (b == NULL) {
                return NGX_ERROR;
            }
			// 将buf拷贝到b中
            ngx_memcpy(b, buf, sizeof(ngx_buf_t));
			// 如果buf在内存中,需要移动pos指针.这里分成了两个buf
            if (ngx_buf_in_memory(buf)) {
                buf->pos += (ssize_t) (NGX_SENDFILE_LIMIT - buf->file_pos);
                b->last = buf->pos;
            }
			// 设置file_pos的位置
            buf->file_pos = NGX_SENDFILE_LIMIT;
            b->file_last = NGX_SENDFILE_LIMIT;
			// 将cl的buf指向b
            cl->buf = b;

        } else {
        // 直接将buf缀接到cl->buf上,处理下一个节点
            cl->buf = buf;
            in = in->next;
        }

#else
	// 直接将in->buf缀接点cl->buf上
        cl->buf = in->buf;
        in = in->next;

#endif
		// 将cl缀接到ll尾部
        cl->next = NULL;
        *ll = cl;
        ll = &cl->next;
    }

    return NGX_OK;
}

/*
	获取根据bsize对齐的buf
*/
static ngx_int_t
ngx_output_chain_align_file_buf(ngx_output_chain_ctx_t *ctx, off_t bsize)
{
    size_t      size;
    ngx_buf_t  *in;

    in = ctx->in->buf;
	// in的file为NULL或者directio标记不存在,直接返回DECLINED
    if (in->file == NULL || !in->file->directio) {
        return NGX_DECLINED;
    }
	// 设置directio
    ctx->directio = 1;
	// 获取对齐的大小,设置默认值
    size = (size_t) (in->file_pos - (in->file_pos & ~(ctx->alignment - 1)));
	// 如果file_pos恰好是对齐的
    if (size == 0) {
		// 判断buf size 和 ctx->bufs.size(全部bufs)的大小
        if (bsize >= (off_t) ctx->bufs.size) {
            return NGX_DECLINED;
        }
		// 将size=bsize
        size = (size_t) bsize;

    } else {
    	// 将size赋值为alignment对齐大小的空缺
        size = (size_t) ctx->alignment - size;
		// 如果size>bsize
        if ((off_t) size > bsize) {
            size = (size_t) bsize;
        }
    }
	// 创建size的temp_buf,并将它缀在ctx->buf
    ctx->buf = ngx_create_temp_buf(ctx->pool, size);
    if (ctx->buf == NULL) {
        return NGX_ERROR;
    }

    /*
     * we do not set ctx->buf->tag, because we do not want
     * to reuse the buf via ctx->free list
     */

#if (NGX_HAVE_ALIGNED_DIRECTIO)
    ctx->unaligned = 1;
#endif

    return NGX_OK;
}

/*
	获取bsize大小的buf
*/
static ngx_int_t
ngx_output_chain_get_buf(ngx_output_chain_ctx_t *ctx, off_t bsize)
{
    size_t       size;
    ngx_buf_t   *b, *in;
    ngx_uint_t   recycled;
	// in chain
    in = ctx->in->buf;
    // 全部的bufs size
    size = ctx->bufs.size;
    recycled = 1;
	// last_in_chain
    if (in->last_in_chain) {
		// bsize < size
        if (bsize < (off_t) size) {

            /*
             * allocate a small temp buf for a small last buf
             * or its small last part
             */

            size = (size_t) bsize;
            recycled = 0;

        } else if (!ctx->directio
                   && ctx->bufs.num == 1
                   && (bsize < (off_t) (size + size / 4)))
        {// 没有directio标记,num==1,bsize<1.25 * size
            /*
             * allocate a temp buf that equals to a last buf,
             * if there is no directio, the last buf size is lesser
             * than 1.25 of bufs.size and the temp buf is single
             */

            size = (size_t) bsize;
            recycled = 0;
        }
    }
	// 获取ngx_buf_t结构体
    b = ngx_calloc_buf(ctx->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }
	// directio标记
    if (ctx->directio) {

        /*
         * allocate block aligned to a disk sector size to enable
         * userland buffer direct usage conjunctly with directio
         */
		// 根据size和alignment计算对齐,因为directio需要对齐
        b->start = ngx_pmemalign(ctx->pool, size, (size_t) ctx->alignment);
        if (b->start == NULL) {
            return NGX_ERROR;
        }

    } else {
    	// 申请size大小
        b->start = ngx_palloc(ctx->pool, size);
        if (b->start == NULL) {
            return NGX_ERROR;
        }
    }

    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + size;
    b->temporary = 1;
    b->tag = ctx->tag;
    b->recycled = recycled;
	// 
    ctx->buf = b;
    // allocated++
    ctx->allocated++;

    return NGX_OK;
}

/*
	将in chain链表中的buf数据拷贝到ctx->buf申请的buf中
*/
static ngx_int_t
ngx_output_chain_copy_buf(ngx_output_chain_ctx_t *ctx)
{
    off_t        size;
    ssize_t      n;
    ngx_buf_t   *src, *dst;
    ngx_uint_t   sendfile;
	// in->buf为src
    src = ctx->in->buf;
	// buf为dst
    dst = ctx->buf;
	// 获取src buf的大小
    size = ngx_buf_size(src);
    // 获取min size
    size = ngx_min(size, dst->end - dst->pos);
	// sendfile存在且非directio
    sendfile = ctx->sendfile && !ctx->directio;

#if (NGX_SENDFILE_LIMIT)
	// 存在in_file而且file_pos >= NGX_SENDFILE_LIMIT
    if (src->in_file && src->file_pos >= NGX_SENDFILE_LIMIT) {
        sendfile = 0;
    }

#endif
	// src在memory中
    if (ngx_buf_in_memory(src)) {
        ngx_memcpy(dst->pos, src->pos, (size_t) size);
        src->pos += (size_t) size;
        dst->last += (size_t) size;
		// 是否在文件中
        if (src->in_file) {
			// 如果sendfile标记存在
            if (sendfile) {
                dst->in_file = 1;
                dst->file = src->file;
                dst->file_pos = src->file_pos;
                dst->file_last = src->file_pos + size;

            } else {
                dst->in_file = 0;
            }

            src->file_pos += size;

        } else {
            dst->in_file = 0;
        }

        if (src->pos == src->last) {
            dst->flush = src->flush;
            dst->last_buf = src->last_buf;
            dst->last_in_chain = src->last_in_chain;
        }

    } else {
    // 不在memory中

#if (NGX_HAVE_ALIGNED_DIRECTIO)

        if (ctx->unaligned) {
            if (ngx_directio_off(src->file->fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, ngx_errno,
                              ngx_directio_off_n " \"%s\" failed",
                              src->file->name.data);
            }
        }

#endif

#if (NGX_HAVE_FILE_AIO)
        if (ctx->aio_handler) {
            n = ngx_file_aio_read(src->file, dst->pos, (size_t) size,
                                  src->file_pos, ctx->pool);
            if (n == NGX_AGAIN) {
                ctx->aio_handler(ctx, src->file);
                return NGX_AGAIN;
            }

        } else
#endif
#if (NGX_THREADS)
        if (ctx->thread_handler) {
            src->file->thread_task = ctx->thread_task;
            src->file->thread_handler = ctx->thread_handler;
            src->file->thread_ctx = ctx->filter_ctx;

            n = ngx_thread_read(src->file, dst->pos, (size_t) size,
                                src->file_pos, ctx->pool);
            if (n == NGX_AGAIN) {
                ctx->thread_task = src->file->thread_task;
                return NGX_AGAIN;
            }

        } else
#endif
        {// 从src->file中读取数据放入到dst
            n = ngx_read_file(src->file, dst->pos, (size_t) size,
                              src->file_pos);
        }

#if (NGX_HAVE_ALIGNED_DIRECTIO)
		// unaligned标记
        if (ctx->unaligned) {
            ngx_err_t  err;

            err = ngx_errno;

            if (ngx_directio_on(src->file->fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, ngx_errno,
                              ngx_directio_on_n " \"%s\" failed",
                              src->file->name.data);
            }

            ngx_set_errno(err);

            ctx->unaligned = 0;
        }

#endif

        if (n == NGX_ERROR) {
            return (ngx_int_t) n;
        }

        if (n != size) {
            ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
                          ngx_read_file_n " read only %z of %O from \"%s\"",
                          n, size, src->file->name.data);
            return NGX_ERROR;
        }

        dst->last += n;

        if (sendfile) {
            dst->in_file = 1;
            dst->file = src->file;
            dst->file_pos = src->file_pos;
            dst->file_last = src->file_pos + n;

        } else {
            dst->in_file = 0;
        }

        src->file_pos += n;
		// 如果file_pos==file_last表示已经加载完成了
        if (src->file_pos == src->file_last) {
            dst->flush = src->flush;
            dst->last_buf = src->last_buf;
            dst->last_in_chain = src->last_in_chain;
        }
    }

    return NGX_OK;
}

/*
	从chain中将数据写出去
*/
ngx_int_t
ngx_chain_writer(void *data, ngx_chain_t *in)
{
    ngx_chain_writer_ctx_t *ctx = data;

    off_t              size;
    ngx_chain_t       *cl, *ln, *chain;
    ngx_connection_t  *c;

    c = ctx->connection;

    for (size = 0; in; in = in->next) {
		// buf_size == 0
        if (ngx_buf_size(in->buf) == 0 && !ngx_buf_special(in->buf)) {

            ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
                          "zero size buf in chain writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          in->buf->temporary,
                          in->buf->recycled,
                          in->buf->in_file,
                          in->buf->start,
                          in->buf->pos,
                          in->buf->last,
                          in->buf->file,
                          in->buf->file_pos,
                          in->buf->file_last);

            ngx_debug_point();

            continue;
        }
		// buf size < 0
        if (ngx_buf_size(in->buf) < 0) {

            ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
                          "negative size buf in chain writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          in->buf->temporary,
                          in->buf->recycled,
                          in->buf->in_file,
                          in->buf->start,
                          in->buf->pos,
                          in->buf->last,
                          in->buf->file,
                          in->buf->file_pos,
                          in->buf->file_last);

            ngx_debug_point();

            return NGX_ERROR;
        }
		// size += buf_size
        size += ngx_buf_size(in->buf);

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "chain writer buf fl:%d s:%uO",
                       in->buf->flush, ngx_buf_size(in->buf));
		// 申请ngx_chain_t结构体对象
        cl = ngx_alloc_chain_link(ctx->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = in->buf;
        cl->next = NULL;
        *ctx->last = cl;
        ctx->last = &cl->next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "chain writer in: %p", ctx->out);
	// 从ctx->out中
    for (cl = ctx->out; cl; cl = cl->next) {
		// buf size == 0
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {

            ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
                          "zero size buf in chain writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();

            continue;
        }

        if (ngx_buf_size(cl->buf) < 0) {

            ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
                          "negative size buf in chain writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();

            return NGX_ERROR;
        }

        size += ngx_buf_size(cl->buf);
    }
	// size == 0
    if (size == 0 && !c->buffered) {
        return NGX_OK;
    }
	// 调用send_chain写出去
    chain = c->send_chain(c, ctx->out, ctx->limit);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "chain writer out: %p", chain);

    if (chain == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }
	// 释放数据
    for (cl = ctx->out; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        ngx_free_chain(ctx->pool, ln);
    }

    ctx->out = chain;

    if (ctx->out == NULL) {
        ctx->last = &ctx->out;

        if (!c->buffered) {
            return NGX_OK;
        }
    }

    return NGX_AGAIN;
}
