
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

/*
	n为元素个数, size为元素大小
*/
ngx_list_t *
ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    ngx_list_t  *list;

    list = ngx_palloc(pool, sizeof(ngx_list_t));
    if (list == NULL) {
        return NULL;
    }

    if (ngx_list_init(list, pool, n, size) != NGX_OK) {
        return NULL;
    }

    return list;
}

/*

*/
void *
ngx_list_push(ngx_list_t *l)
{
    void             *elt;
    ngx_list_part_t  *last;
	// 获取last节点
    last = l->last;
	// 判断是否已经满了,条件是nelts == nalloc
    if (last->nelts == l->nalloc) {

        /* the last part is full, allocate a new list part */
		// 最后一个满了,申请一个list节点
        last = ngx_palloc(l->pool, sizeof(ngx_list_part_t));
        if (last == NULL) {
            return NULL;
        }
		// 每个节点申请nalloc * size个数组节点
        last->elts = ngx_palloc(l->pool, l->nalloc * l->size);
        if (last->elts == NULL) {
            return NULL;
        }

        last->nelts = 0;
        last->next = NULL;
		// 更新last指针
        l->last->next = last;
        l->last = last;
    }
	// 找到最近空闲的数组节点
    elt = (char *) last->elts + l->size * last->nelts;
    // 更新nelts
    last->nelts++;

    return elt;
}
