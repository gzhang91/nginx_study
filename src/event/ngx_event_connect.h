
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_CONNECT_H_INCLUDED_
#define _NGX_EVENT_CONNECT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_PEER_KEEPALIVE           1
#define NGX_PEER_NEXT                2
#define NGX_PEER_FAILED              4


typedef struct ngx_peer_connection_s  ngx_peer_connection_t;

typedef ngx_int_t (*ngx_event_get_peer_pt)(ngx_peer_connection_t *pc,
    void *data);
typedef void (*ngx_event_free_peer_pt)(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state);
typedef void (*ngx_event_notify_peer_pt)(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type);
typedef ngx_int_t (*ngx_event_set_peer_session_pt)(ngx_peer_connection_t *pc,
    void *data);
typedef void (*ngx_event_save_peer_session_pt)(ngx_peer_connection_t *pc,
    void *data);


struct ngx_peer_connection_s {
	// 连接指针
    ngx_connection_t                *connection;
	// 地址指针
    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;
    ngx_str_t                       *name;
	// 重试次数
    ngx_uint_t                       tries;
    // 开始连接时间
    ngx_msec_t                       start_time;
	// 获取，释放，通知 回调函数句柄
    ngx_event_get_peer_pt            get;
    ngx_event_free_peer_pt           free;
    ngx_event_notify_peer_pt         notify;
    // 回调函数参数
    void                            *data;

#if (NGX_SSL || NGX_COMPAT)
    ngx_event_set_peer_session_pt    set_session;
    ngx_event_save_peer_session_pt   save_session;
#endif
	// 本地地址
    ngx_addr_t                      *local;
	// 类型：SOCK_STREAM, SOCK_DATAGRAM等
    int                              type;
    // 接收缓冲区大小
    int                              rcvbuf;

    ngx_log_t                       *log;

    unsigned                         cached:1;
    // IP_TRANSPARENT标记
    unsigned                         transparent:1;
    // socket的SO_KEEPALIVE标记
    unsigned                         so_keepalive:1;
    // down标记
    unsigned                         down:1;

                                     /* ngx_connection_log_error_e */
    unsigned                         log_error:2;

    NGX_COMPAT_BEGIN(2)
    NGX_COMPAT_END
};


ngx_int_t ngx_event_connect_peer(ngx_peer_connection_t *pc);
ngx_int_t ngx_event_get_peer(ngx_peer_connection_t *pc, void *data);


#endif /* _NGX_EVENT_CONNECT_H_INCLUDED_ */
