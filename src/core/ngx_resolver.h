
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef _NGX_RESOLVER_H_INCLUDED_
#define _NGX_RESOLVER_H_INCLUDED_


#define NGX_RESOLVE_A         1
#define NGX_RESOLVE_CNAME     5
#define NGX_RESOLVE_PTR       12
#define NGX_RESOLVE_MX        15
#define NGX_RESOLVE_TXT       16
#if (NGX_HAVE_INET6)
#define NGX_RESOLVE_AAAA      28
#endif
#define NGX_RESOLVE_SRV       33
#define NGX_RESOLVE_DNAME     39

#define NGX_RESOLVE_FORMERR   1
#define NGX_RESOLVE_SERVFAIL  2
#define NGX_RESOLVE_NXDOMAIN  3
#define NGX_RESOLVE_NOTIMP    4
#define NGX_RESOLVE_REFUSED   5
#define NGX_RESOLVE_TIMEDOUT  NGX_ETIMEDOUT


#define NGX_NO_RESOLVER       (void *) -1

#define NGX_RESOLVER_MAX_RECURSION    50


typedef struct ngx_resolver_s  ngx_resolver_t;


typedef struct {
    ngx_connection_t         *udp;
    ngx_connection_t         *tcp;
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
    ngx_str_t                 server;
    ngx_log_t                 log;
    ngx_buf_t                *read_buf;
    ngx_buf_t                *write_buf;
    ngx_resolver_t           *resolver;
} ngx_resolver_connection_t;


typedef struct ngx_resolver_ctx_s  ngx_resolver_ctx_t;

typedef void (*ngx_resolver_handler_pt)(ngx_resolver_ctx_t *ctx);


typedef struct {
	// sockaddr 地址
    struct sockaddr          *sockaddr;
    // socklen 地址长度
    socklen_t                 socklen;
    // string 名字
    ngx_str_t                 name;
    // 优先级
    u_short                   priority;
    // 权重
    u_short                   weight;
} ngx_resolver_addr_t;


typedef struct {
	// name
    ngx_str_t                 name;
    // 优先级
    u_short                   priority;
    // 权重
    u_short                   weight;
    // 端口
    u_short                   port;
} ngx_resolver_srv_t;


typedef struct {
	// name
    ngx_str_t                 name;
    // 优先级
    u_short                   priority;
    // 权重
    u_short                   weight;
    // 端口
    u_short                   port;
	// ctx上下文
    ngx_resolver_ctx_t       *ctx;
    // 状态
    ngx_int_t                 state;
	// addr的个数
    ngx_uint_t                naddrs;
    // addr数组
    ngx_addr_t               *addrs;
} ngx_resolver_srv_name_t;


typedef struct {
	// 红黑树node
    ngx_rbtree_node_t         node;
    // queue
    ngx_queue_t               queue;

    /* PTR: resolved name, A: name to resolve */
    u_char                   *name;

#if (NGX_HAVE_INET6)
    /* PTR: IPv6 address to resolve (IPv4 address is in rbtree node key) */
    struct in6_addr           addr6;
#endif
	// 红黑树node个数?
    u_short                   nlen;
    // queue node个数?
    u_short                   qlen;
	// 查询字符串
    u_char                   *query;
#if (NGX_HAVE_INET6)
    u_char                   *query6;
#endif

    union {
        in_addr_t             addr;
        in_addr_t            *addrs;
        u_char               *cname;
        ngx_resolver_srv_t   *srvs;
    } u;

    u_char                    code;
    u_short                   naddrs;
    u_short                   nsrvs;
    u_short                   cnlen;

#if (NGX_HAVE_INET6)
    union {
        struct in6_addr       addr6;
        struct in6_addr      *addrs6;
    } u6;

    u_short                   naddrs6;
#endif
	// 到期时间
    time_t                    expire;
    // 有效时间
    time_t                    valid;
    // ttl跳数
    uint32_t                  ttl;
	// ip标记
    unsigned                  tcp:1;
#if (NGX_HAVE_INET6)
	// ipv6标记
    unsigned                  tcp6:1;
#endif
	// 上一次connection
    ngx_uint_t                last_connection;
	// waiting ctx上下文
    ngx_resolver_ctx_t       *waiting;
} ngx_resolver_node_t;


struct ngx_resolver_s {
    /* has to be pointer because of "incomplete type" */
    // event
    ngx_event_t              *event;
    // 参数
    void                     *dummy;
    // log标记
    ngx_log_t                *log;

    /* event ident must be after 3 pointers as in ngx_connection_t */
    ngx_int_t                 ident;

    /* simple round robin DNS peers balancer */
    // connection数组
    ngx_array_t               connections;
    // 
    ngx_uint_t                last_connection;
	// 名字rbtree
    ngx_rbtree_t              name_rbtree;
    // 结束节点
    ngx_rbtree_node_t         name_sentinel;
	// 服务rbtree
    ngx_rbtree_t              srv_rbtree;
    ngx_rbtree_node_t         srv_sentinel;
	// 地址tbtree
    ngx_rbtree_t              addr_rbtree;
    ngx_rbtree_node_t         addr_sentinel;
	// 名字重新发送queue ?
    ngx_queue_t               name_resend_queue;
    // 服务重新发送queue ?
    ngx_queue_t               srv_resend_queue;
    // 地址重新发送queue ?
    ngx_queue_t               addr_resend_queue;
	// 名字到期queue
    ngx_queue_t               name_expire_queue;
    // 服务到期queue
    ngx_queue_t               srv_expire_queue;
    // 地址到期queue
    ngx_queue_t               addr_expire_queue;

#if (NGX_HAVE_INET6)
    ngx_uint_t                ipv6;                 /* unsigned  ipv6:1; */
    ngx_rbtree_t              addr6_rbtree;
    ngx_rbtree_node_t         addr6_sentinel;
    ngx_queue_t               addr6_resend_queue;
    ngx_queue_t               addr6_expire_queue;
#endif
	// 重新send timeout
    time_t                    resend_timeout;
    // tcp链接timeout
    time_t                    tcp_timeout;
    // 到期时间
    time_t                    expire;
    // 有效时间
    time_t                    valid;
	// 日志级别
    ngx_uint_t                log_level;
};


struct ngx_resolver_ctx_s {
	// ctx缀成链表
    ngx_resolver_ctx_t       *next;
    // reolver_t句柄
    ngx_resolver_t           *resolver;
    // 红黑树node
    ngx_resolver_node_t      *node;

    /* event ident must be after 3 pointers as in ngx_connection_t */
    ngx_int_t                 ident;
	// state
    ngx_int_t                 state;
    // name名字
    ngx_str_t                 name;
    // service名字
    ngx_str_t                 service;
	// 有效时间
    time_t                    valid;
    // addrs个数
    ngx_uint_t                naddrs;
    // addrs地址
    ngx_resolver_addr_t      *addrs;
    // address
    ngx_resolver_addr_t       addr;
    // ipv4地址
    struct sockaddr_in        sin;
	// 计数
    ngx_uint_t                count;
    // srv个数
    ngx_uint_t                nsrvs;
    // srv解析的数组
    ngx_resolver_srv_name_t  *srvs;
	// handler
    ngx_resolver_handler_pt   handler;
    // 数据
    void                     *data;
    // timeout
    ngx_msec_t                timeout;
	// 快速标记
    unsigned                  quick:1;
    // async异步标记
    unsigned                  async:1;
    // 可取消标记
    unsigned                  cancelable:1;
    // 递归解析标记
    ngx_uint_t                recursion;
    // event指针
    ngx_event_t              *event;
};


ngx_resolver_t *ngx_resolver_create(ngx_conf_t *cf, ngx_str_t *names,
    ngx_uint_t n);
ngx_resolver_ctx_t *ngx_resolve_start(ngx_resolver_t *r,
    ngx_resolver_ctx_t *temp);
ngx_int_t ngx_resolve_name(ngx_resolver_ctx_t *ctx);
void ngx_resolve_name_done(ngx_resolver_ctx_t *ctx);
ngx_int_t ngx_resolve_addr(ngx_resolver_ctx_t *ctx);
void ngx_resolve_addr_done(ngx_resolver_ctx_t *ctx);
char *ngx_resolver_strerror(ngx_int_t err);


#endif /* _NGX_RESOLVER_H_INCLUDED_ */
