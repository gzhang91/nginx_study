
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_listening_s  ngx_listening_t;
// 监听结构 - 只有一个本地监听套接字地址就行
struct ngx_listening_s {
	// 监听fd
    ngx_socket_t        fd;
	// 监听地址
    struct sockaddr    *sockaddr;
    // 监听地址长度
    socklen_t           socklen;    /* size of sockaddr */
	// 监听地址字符串表示
    ngx_str_t           addr_text;
    // 监听地址字符串最大长度
    size_t              addr_text_max_len;
    
	// 类型: SOCK_STREAM, SOCK_DRAM等类型
    int                 type;
	// listen的backlog
    int                 backlog;
    // receive buf的大小
    int                 rcvbuf;
    // send buf的大小
    int                 sndbuf;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                 keepidle;
    int                 keepintvl;
    int                 keepcnt;
#endif

    /* handler of accepted connection */
    // accept 成功后的回调函数
    ngx_connection_handler_pt   handler;
	// servers
    void               *servers;  /* array of ngx_http_in_addr_t, for example */
	// log句柄
    ngx_log_t           log;
    // log句柄指针
    ngx_log_t          *logp;
	// 内存池大小
    size_t              pool_size;
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;
    /* should be here because of the deferred accept */
    ngx_msec_t          post_accept_timeout;
	// 前一个listen指针
    ngx_listening_t    *previous;
	// 监听句柄代表的连接指针
    ngx_connection_t   *connection;
	// rbtree root根
    ngx_rbtree_t        rbtree;
    // 尾节点
    ngx_rbtree_node_t   sentinel;
	// 标记本listen socket放在哪个worker_processes上
    ngx_uint_t          worker;
	// 打开标记
    unsigned            open:1;
    // 是否继续保留
    unsigned            remain:1;
    // ignore标记
    unsigned            ignore:1;

    unsigned            bound:1;       /* already bound */
    unsigned            inherited:1;   /* inherited from previous process */
    unsigned            nonblocking_accept:1;
    // 是否是listen标记
    unsigned            listen:1;
    // 非阻塞标记
    unsigned            nonblocking:1;
    unsigned            shared:1;    /* shared between threads or processes */
    unsigned            addr_ntop:1;
    unsigned            wildcard:1;

#if (NGX_HAVE_INET6)
    unsigned            ipv6only:1;
#endif
	// 重用端口标记
    unsigned            reuseport:1;
    unsigned            add_reuseport:1;
    unsigned            keepalive:2;
	// 延迟accept标记,延迟accept意思是等到数据到来时才accept成功,只是连接而不发送数据则只能标记为acked
    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char               *accept_filter;
#endif
#if (NGX_HAVE_SETFIB)
    int                 setfib;
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    int                 fastopen;
#endif

};


typedef enum {
    NGX_ERROR_ALERT = 0,
    NGX_ERROR_ERR,
    NGX_ERROR_INFO,
    NGX_ERROR_IGNORE_ECONNRESET,
    NGX_ERROR_IGNORE_EINVAL
} ngx_connection_log_error_e;


typedef enum {
    NGX_TCP_NODELAY_UNSET = 0,
    NGX_TCP_NODELAY_SET,
    NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;


typedef enum {
    NGX_TCP_NOPUSH_UNSET = 0,
    NGX_TCP_NOPUSH_SET,
    NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;


#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01
#define NGX_HTTP_V2_BUFFERED   0x02

// connection结构体 - 
struct ngx_connection_s {
	// 对于空闲链表会用来当做next指针串接起来
    void               *data;
    // read event指针
    ngx_event_t        *read;
    // write event指针
    ngx_event_t        *write;
	// connection对应的套接字
    ngx_socket_t        fd;
	// recv函数指针
    ngx_recv_pt         recv;
    // send函数指针
    ngx_send_pt         send;
    // recv chain函数指针
    ngx_recv_chain_pt   recv_chain;
    // send chain函数指针
    ngx_send_chain_pt   send_chain;
	// 是否是listen socket
    ngx_listening_t    *listening;
	// sent数据量
    off_t               sent;
	// log句柄指针
    ngx_log_t          *log;
	// 内存池pool指针
    ngx_pool_t         *pool;
	// 类型: SOCK_STREAM, SOCK_DRAM等类型
    int                 type;
	// 套接字地址
    struct sockaddr    *sockaddr;
    // 套接字地址长度
    socklen_t           socklen;
    // 套接字字符串
    ngx_str_t           addr_text;
	// 代理协议地址
    ngx_str_t           proxy_protocol_addr;
	// 代理协议端口
    in_port_t           proxy_protocol_port;

#if (NGX_SSL || NGX_COMPAT)
    ngx_ssl_connection_t  *ssl;
#endif
	// 如果是udp
    ngx_udp_connection_t  *udp;
	// 本地套接字地址
    struct sockaddr    *local_sockaddr;
    // 本地套接字地址长度
    socklen_t           local_socklen;
	// 缓冲区
    ngx_buf_t          *buffer;
	// 队列
    ngx_queue_t         queue;
	
    ngx_atomic_uint_t   number;
	// requests计数
    ngx_uint_t          requests;
	// 缓存大小
    unsigned            buffered:8;
	
    unsigned            log_error:3;     /* ngx_connection_log_error_e */
	// 是否超时
    unsigned            timedout:1;
    unsigned            error:1;
    // 摧毁标记
    unsigned            destroyed:1;
	// 闲置标记
    unsigned            idle:1;
    // 重用标记
    unsigned            reusable:1;
    // 关闭标记
    unsigned            close:1;
    // 共享标记
    unsigned            shared:1;
	// sendfile标记
    unsigned            sendfile:1;
    // 发送lowat
    unsigned            sndlowat:1;
    // tcp_nodelay标记
    unsigned            tcp_nodelay:2;   /* ngx_connection_tcp_nodelay_e */
    // tcp_nopush标记
    unsigned            tcp_nopush:2;    /* ngx_connection_tcp_nopush_e */
	// 是否为need_last_buf标记
    unsigned            need_last_buf:1;

#if (NGX_HAVE_AIO_SENDFILE || NGX_COMPAT)
    unsigned            busy_count:2;
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_thread_task_t  *sendfile_task;
#endif
};


#define ngx_set_connection_log(c, l)                                         \
                                                                             \
    c->log->file = l->file;                                                  \
    c->log->next = l->next;                                                  \
    c->log->writer = l->writer;                                              \
    c->log->wdata = l->wdata;                                                \
    if (!(c->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {                   \
        c->log->log_level = l->log_level;                                    \
    }


ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, struct sockaddr *sockaddr,
    socklen_t socklen);
ngx_int_t ngx_clone_listening(ngx_cycle_t *cycle, ngx_listening_t *ls);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
void ngx_close_idle_connections(ngx_cycle_t *cycle);
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
    ngx_uint_t port);
ngx_int_t ngx_tcp_nodelay(ngx_connection_t *c);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);

ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
void ngx_free_connection(ngx_connection_t *c);

void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);

#endif /* _NGX_CONNECTION_H_INCLUDED_ */
