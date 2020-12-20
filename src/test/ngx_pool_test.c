#include <stdio.h>
#include <ngx_core.h>

typedef struct student {
	ngx_str_t name;
	unsigned short age;
	char detail[];
} student;

typedef struct product {
	ngx_int_t id;
	char info[4096];
} product;

void Print(struct student* st) {
	size_t i = 0;
	if (st == NULL) {
		return;
	}

	printf("name> ");
	//(void) ngx_write_fd(ngx_stdout, "name> ",
    //                                strlen("name> "));
	for (; i < st->name.len; i++) {
		printf("%c", st->name.data[i]);
		
	}
	//(void) ngx_write_fd(ngx_stdout, st->name.data,
    //                                st->name.len);
    //(void) ngx_write_fd(ngx_stdout, "\n",
    //                                strlen("\n"));
	printf("\n");

	printf("age> %d\n", st->age);
	printf("detail> %s\n", st->detail);
	//(void) ngx_write_fd(ngx_stdout, st->detail,
    //                                strlen(st->detail));
    //(void) ngx_write_fd(ngx_stdout, "\n",
    //                                strlen("\n"));
	
}

u_char *name_const[] = {(u_char *)"gzhang", (u_char *)"liling", (u_char *)"wan"};

int main() {
	if (ngx_strerror_init() != NGX_OK) {
		return 1;
	}

	ngx_log_t *log = ngx_log_init(NULL);

	// 使用pool初始化,ngx_pagesize现在还没有初始化哦,别乱用
	ngx_pool_t *pool = ngx_create_pool(512, log);
	(void)pool;

	// 在内存池中申请结构体
	struct student *stu1 = ngx_palloc(pool, sizeof(struct student) + strlen("A beatiful man") + 1);
	u_char *name1_str = ngx_palloc(pool, sizeof(u_char) * 6);
	memcpy(name1_str, name_const[0], 6);
	stu1->name.data = name1_str;
	stu1->name.len = 6;
	stu1->age = 21;
	memcpy(stu1->detail, "A beatiful man", strlen("A beatiful man"));
	stu1->detail[strlen("A beatiful men")] = 0;
	
	struct student *stu2 = ngx_palloc(pool, sizeof(struct student) + strlen("A beatiful women") + 1);
	u_char *name2_str = ngx_palloc(pool, sizeof(u_char) * 6);
	memcpy(name2_str, name_const[1], 6);
	stu2->name.data = name2_str;
	stu2->name.len = 6;
	stu2->age = 21;
	memcpy(stu2->detail, "A beatiful women", strlen("A beatiful women"));
	stu2->detail[strlen("A beatiful women")] = 0;

	ngx_pool_show_info(pool);

	struct student *stu3 = ngx_palloc(pool, sizeof(struct student) + 400);
	u_char *name3_str = ngx_palloc(pool, sizeof(u_char) * 4);
	memcpy(name3_str, name_const[2], 4);
	stu3->name.data = name3_str;
	stu3->name.len = 4;
	stu3->age = 21;
	memcpy(stu3->detail, "A beatiful women", strlen("A beatiful women"));
	stu3->detail[strlen("A beatiful women")] = 0;

	ngx_pool_show_info(pool);

	//Print(stu1);
	//Print(stu2);
	//Print(stu3)

	struct product *pro1 = ngx_palloc(pool, sizeof(product));
	pro1->id = 1;
	memset(pro1->info, 0x0, sizeof(pro1->info));
	memcpy(pro1->info, "hello", strlen("hello"));
	(void)pro1;

	ngx_pool_show_info(pool);

	struct product *pro2 = ngx_palloc(pool, sizeof(product));
	pro1->id = 2;
	memset(pro1->info, 0x0, sizeof(pro1->info));
	memcpy(pro1->info, "world", strlen("hello"));
	(void)pro2;

	ngx_pool_show_info(pool);

	ngx_destroy_pool(pool);

	//printf("hello world\n");
}

