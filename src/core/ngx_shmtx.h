
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMTX_H_INCLUDED_
#define _NGX_SHMTX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
	// lock 锁对象
    ngx_atomic_t   lock;
#if (NGX_HAVE_POSIX_SEM)
	// sem 锁对象
    ngx_atomic_t   wait;
#endif
} ngx_shmtx_sh_t;


typedef struct {
#if (NGX_HAVE_ATOMIC_OPS)
	// lock 锁指针
    ngx_atomic_t  *lock;
#if (NGX_HAVE_POSIX_SEM)
	// sem 锁指针
    ngx_atomic_t  *wait;
    // 信号量个数
    ngx_uint_t     semaphore;
    // 信号量
    sem_t          sem;
#endif
#else
	// 文件锁fd
    ngx_fd_t       fd;
    // 文件名字
    u_char        *name;
#endif
	// spin 个数
    ngx_uint_t     spin;
} ngx_shmtx_t;


ngx_int_t ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr,
    u_char *name);
void ngx_shmtx_destroy(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_trylock(ngx_shmtx_t *mtx);
void ngx_shmtx_lock(ngx_shmtx_t *mtx);
void ngx_shmtx_unlock(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid);


#endif /* _NGX_SHMTX_H_INCLUDED_ */
