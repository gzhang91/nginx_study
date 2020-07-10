#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdio.h>
#include <string.h>

static char *ngx_http_struct_test(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_struct_commands[] = {

    { ngx_string("test_struct"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_struct_test,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_struct_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,        /* create location configuration */
    NULL /* merge location configuration */
};


ngx_module_t  ngx_http_mystruct_module = {
    NGX_MODULE_V1,
    &ngx_http_struct_module_ctx,            /* module context */
    ngx_http_struct_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

///////////////////////////////////////////////
static void string_test() {
	// string test
	ngx_str_t str;
	str.data = (u_char *)"hello world";
	str.len = strlen("hello world");

	u_char* data = (u_char *)malloc(str.len + 1);
	ngx_memset(data, 0, str.len + 1);
	(void)ngx_cpymem(data, str.data, str.len);

	printf("String test: %s\n", data);
}

static void list_test(ngx_conf_t *cf) {
	ngx_list_t *lst = NULL;
	ngx_uint_t idx = 0, count = 0;
	struct Persion {
		char name[32];
		int age;
	};

	lst = ngx_list_create(cf->pool, 2, sizeof(struct Persion));

	struct Persion *p1 = ngx_list_push(lst);
	ngx_memcpy(p1->name, "gzhang", sizeof("gzhang")); 
	p1->age = 23;
	
	struct Persion *p2 = ngx_list_push(lst);
	ngx_memcpy(p2->name, "wanwan", sizeof("wanwan")); 
	p2->age = 21;

	struct Persion *p3 = ngx_list_push(lst);
	ngx_memcpy(p3->name, "liling", sizeof("liling")); 
	p3->age = 26;

	struct Persion *p4 = ngx_list_push(lst);
	ngx_memcpy(p4->name, "liting", sizeof("liting")); 
	p4->age = 26;

	ngx_list_part_t *part = &lst->part;

	do {
		printf("NODE %ld \n", count);
		struct Persion *p = (struct Persion *)part->elts;
		for (idx = 0; idx < part->nelts; idx++) {
			printf("name: %s, age: %d  ", p->name, p->age);
			p++;
		}

		printf("\n");
		count ++;
		part = part->next;
	} while (part != NULL);
}

static char *
ngx_http_struct_test(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    // ngx_http_index_loc_conf_t *ilcf = conf;

    printf("test struct\n");

	string_test();
	list_test(cf);

    return NGX_CONF_OK;
}

