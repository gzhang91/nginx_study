
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef _NGX_OPEN_FILE_CACHE_H_INCLUDED_
#define _NGX_OPEN_FILE_CACHE_H_INCLUDED_


#define NGX_OPEN_FILE_DIRECTIO_OFF  NGX_MAX_OFF_T_VALUE


typedef struct {
	// 文件描述符
    ngx_fd_t                 fd;
    // uniq编号
    ngx_file_uniq_t          uniq;
    // 修改时间
    time_t                   mtime;
    // 大小
    off_t                    size;
    // 文件大小
    off_t                    fs_size;
    // directio
    off_t                    directio;
    // 提前预读
    size_t                   read_ahead;
	// 错误标记
    ngx_err_t                err;
    // 失败原因
    char                    *failed;
	// 失效时间
    time_t                   valid;
	// 最小使用次数
    ngx_uint_t               min_uses;

#if (NGX_HAVE_OPENAT)
	// 存在openat系统调用,openat与open的区别可以在man中了解
    size_t                   disable_symlinks_from;
    unsigned                 disable_symlinks:2;
#endif
	// 是否为test_dir
    unsigned                 test_dir:1;
    // 是否只是测试
    unsigned                 test_only:1;
    // 是否为log标记
    unsigned                 log:1;
	// 是否报错
    unsigned                 errors:1;
    // 是否为事件标记
    unsigned                 events:1;
	// 是否为目录
    unsigned                 is_dir:1;
    // 是否为文件
    unsigned                 is_file:1;
    // 是否为符号链接
    unsigned                 is_link:1;
    // 是否可执行
    unsigned                 is_exec:1;
    // 是否为directio
    unsigned                 is_directio:1;
} ngx_open_file_info_t;


typedef struct ngx_cached_open_file_s  ngx_cached_open_file_t;

struct ngx_cached_open_file_s {
	// rbtree node
    ngx_rbtree_node_t        node;
    // queue节点
    ngx_queue_t              queue;
	// 名字
    u_char                  *name;
    // create time
    time_t                   created;
    // acess time
    time_t                   accessed;
	// 文件描述符
    ngx_fd_t                 fd;
    // 唯一号
    ngx_file_uniq_t          uniq;
    // modify time
    time_t                   mtime;
    // 大小
    off_t                    size;
    // error code
    ngx_err_t                err;
	// 使用计数
    uint32_t                 uses;

#if (NGX_HAVE_OPENAT)
    size_t                   disable_symlinks_from;
    unsigned                 disable_symlinks:2;
#endif
	// count计数
    unsigned                 count:24;
    // close标记
    unsigned                 close:1;
    // use_event标记
    unsigned                 use_event:1;
	// dir标记
    unsigned                 is_dir:1;
    // 文件标记
    unsigned                 is_file:1;
    // 链接文件标记
    unsigned                 is_link:1;
    // 可执行标记
    unsigned                 is_exec:1;
    // 是否为directio
    unsigned                 is_directio:1;
	// event句柄
    ngx_event_t             *event;
};


typedef struct {
	// rbtree 控制结构
    ngx_rbtree_t             rbtree;
    // 尾节点
    ngx_rbtree_node_t        sentinel;
    // 到期队列
    ngx_queue_t              expire_queue;
	// 当前计数
    ngx_uint_t               current;
    // 最大计数
    ngx_uint_t               max;
    // 非active时间
    time_t                   inactive;
} ngx_open_file_cache_t;


typedef struct {
	// open file cache结构体
    ngx_open_file_cache_t   *cache;
    // cached open file结构体指针
    ngx_cached_open_file_t  *file;
    // 最小使用数
    ngx_uint_t               min_uses;
    // log指针
    ngx_log_t               *log;
} ngx_open_file_cache_cleanup_t;


typedef struct {

    /* ngx_connection_t stub to allow use c->fd as event ident */
    // 数据指针
    void                    *data;
    // read,write 事件指针
    ngx_event_t             *read;
    ngx_event_t             *write;
    // fd
    ngx_fd_t                 fd;
	// cached open file结构体指针
    ngx_cached_open_file_t  *file;
    // open file cache结构体
    ngx_open_file_cache_t   *cache;
} ngx_open_file_cache_event_t;


ngx_open_file_cache_t *ngx_open_file_cache_init(ngx_pool_t *pool,
    ngx_uint_t max, time_t inactive);
ngx_int_t ngx_open_cached_file(ngx_open_file_cache_t *cache, ngx_str_t *name,
    ngx_open_file_info_t *of, ngx_pool_t *pool);


#endif /* _NGX_OPEN_FILE_CACHE_H_INCLUDED_ */
