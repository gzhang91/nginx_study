
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

struct ngx_shm_zone_s {
	// data是next指针
    void                     *data;
    // 共享内存节点数据结构
    ngx_shm_t                 shm;
    // shm_zone初始化函数指针
    ngx_shm_zone_init_pt      init;
    // 根据tag判断共享内存zone
    void                     *tag;
    // sync
    void                     *sync;
    // noreuse 标记
    ngx_uint_t                noreuse;  /* unsigned  noreuse:1; */
};


struct ngx_cycle_s {
	// conf_ctx 
    void                  ****conf_ctx;
    // pool内存池指针
    ngx_pool_t               *pool;
	// 日志句柄
    ngx_log_t                *log;
    // 新的日志句柄
    ngx_log_t                 new_log;
	// stderr标记
    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */
	// files来保存connection
    ngx_connection_t        **files;
	// 空闲connection链表
    ngx_connection_t         *free_connections;
    ngx_uint_t                free_connection_n;
	// module列表
    ngx_module_t            **modules;
	// modules的总数
    ngx_uint_t                modules_n;
	// 使用的modules
    ngx_uint_t                modules_used;    /* unsigned  modules_used:1; */
	// reusable_connections_queue重用connections队列
    ngx_queue_t               reusable_connections_queue;
	// reusable_connections_n重用connection队列大小
    ngx_uint_t                reusable_connections_n;
	// listen 句柄列表
    ngx_array_t               listening;
	// paths列表
    ngx_array_t               paths;
	// 配置dump列表
    ngx_array_t               config_dump;
    // 配置dump的红黑树节点
    ngx_rbtree_t              config_dump_rbtree;
    // 配置dump的红黑树结束节点
    ngx_rbtree_node_t         config_dump_sentinel;
	// 打开的文件list
    ngx_list_t                open_files;
    // 共享内存list
    ngx_list_t                shared_memory;
	// 打开的connection的数量
    ngx_uint_t                connection_n;
	// 打开的文件个数
    ngx_uint_t                files_n;
	// 打开的connection的列表
    ngx_connection_t         *connections;
    // read event
    ngx_event_t              *read_events;
	// write event
    ngx_event_t              *write_events;
	// 之前的old_cycle
    ngx_cycle_t              *old_cycle;
	// 配置文件路径字符串
    ngx_str_t                 conf_file;
    // -g配置参数字符串
    ngx_str_t                 conf_param;
	// 配置文件的前缀
    ngx_str_t                 conf_prefix;
    // 输出文件的前缀
    ngx_str_t                 prefix;
    // lock文件的路径
    ngx_str_t                 lock_file;
    // hostname字符串
    ngx_str_t                 hostname;
};


typedef struct {
	// daemon标记
    ngx_flag_t                daemon;
    // master标记
    ngx_flag_t                master;
	// timer_resolution定时器精确度
    ngx_msec_t                timer_resolution;
    // shutdown的timeout
    ngx_msec_t                shutdown_timeout;
	// worker process的个数
    ngx_int_t                 worker_processes;
    // ?
    ngx_int_t                 debug_points;
	// 打开文件数目大小
    ngx_int_t                 rlimit_nofile;
    // 生成core文件大小
    off_t                     rlimit_core;
	// 优先级
    int                       priority;
	// cpu亲和力
    ngx_uint_t                cpu_affinity_auto;
    ngx_uint_t                cpu_affinity_n;
    ngx_cpuset_t             *cpu_affinity;
	// 用户名?
    char                     *username;
    // 用户id
    ngx_uid_t                 user;
    // 组id
    ngx_gid_t                 group;
	// 工作目录
    ngx_str_t                 working_directory;
	// lock文件的路径
    ngx_str_t                 lock_file;
	// 进程pid字符串
    ngx_str_t                 pid;
    // 旧的pid字符串
    ngx_str_t                 oldpid;
	// 环境变量
    ngx_array_t               env;
    // raw的环境变量
    char                    **environment;
	// ?
    ngx_uint_t                transparent;  /* unsigned  transparent:1; */
} ngx_core_conf_t;


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
ngx_cpuset_t *ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);
void ngx_set_shutdown_timer(ngx_cycle_t *cycle);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_dump_config;
extern ngx_uint_t             ngx_quiet_mode;


#endif /* _NGX_CYCLE_H_INCLUDED_ */
