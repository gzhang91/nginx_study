
/*
 * Copyright (C) Ruslan Ermilov
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_HAVE_ATOMIC_OPS)


#define NGX_RWLOCK_SPIN   2048
#define NGX_RWLOCK_WLOCK  ((ngx_atomic_uint_t) -1)


void
ngx_rwlock_wlock(ngx_atomic_t *lock)
{
    ngx_uint_t  i, n;

    for ( ;; ) {
    	// 如果*lock==0表示没有设置
		// 比较*lock与old(0)的值,相等设置*lock=NGX_RWLOCK_WLOCK,返回1
        if (*lock == 0 && ngx_atomic_cmp_set(lock, 0, NGX_RWLOCK_WLOCK)) {
            return;
        }
		// lock已经占用了
        if (ngx_ncpu > 1) {

            for (n = 1; n < NGX_RWLOCK_SPIN; n <<= 1) {
				// 先pause之后再检测
                for (i = 0; i < n; i++) {
                    ngx_cpu_pause();
                }
				// 重新检测,设置
                if (*lock == 0
                    && ngx_atomic_cmp_set(lock, 0, NGX_RWLOCK_WLOCK))
                {
                    return;
                }
            }
        }
		// 进行这么多尝试后,发现不成功,直接让出CPU
        ngx_sched_yield();
    }
}


void
ngx_rwlock_rlock(ngx_atomic_t *lock)
{
    ngx_uint_t         i, n;
    ngx_atomic_uint_t  readers;

    for ( ;; ) {
    	// 获取*lock的值,即readers
        readers = *lock;
		// 如果readers不为wlock,表示可以任意读了
		// 比较readers与old(readers)的值,相等设置*lock=readers+1,返回1
        if (readers != NGX_RWLOCK_WLOCK
            && ngx_atomic_cmp_set(lock, readers, readers + 1))
        {
            return;
        }

        if (ngx_ncpu > 1) {

            for (n = 1; n < NGX_RWLOCK_SPIN; n <<= 1) {
				// spin旋转一会
                for (i = 0; i < n; i++) {
                    ngx_cpu_pause();
                }
				// 重新进行检测
                readers = *lock;

                if (readers != NGX_RWLOCK_WLOCK
                    && ngx_atomic_cmp_set(lock, readers, readers + 1))
                {
                    return;
                }
            }
        }
		// 实在获取不到就让出CPU
        ngx_sched_yield();
    }
}


void
ngx_rwlock_unlock(ngx_atomic_t *lock)
{
    ngx_atomic_uint_t  readers;

    readers = *lock;
	// 如果readers == WLOCK,直接设置释放出来
    if (readers == NGX_RWLOCK_WLOCK) {
        (void) ngx_atomic_cmp_set(lock, NGX_RWLOCK_WLOCK, 0);
        return;
    }

    for ( ;; ) {
		// 减少readers
        if (ngx_atomic_cmp_set(lock, readers, readers - 1)) {
            return;
        }

        readers = *lock;
    }
}


void
ngx_rwlock_downgrade(ngx_atomic_t *lock)
{
    if (*lock == NGX_RWLOCK_WLOCK) {
        *lock = 1;
    }
}


#else

#if (NGX_HTTP_UPSTREAM_ZONE || NGX_STREAM_UPSTREAM_ZONE)

#error ngx_atomic_cmp_set() is not defined!

#endif

#endif
