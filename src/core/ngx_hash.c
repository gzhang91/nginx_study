
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

/*
	哈希查找函数,先根据key从buckets找到elt,然后根据name判断是否相等
	== bucket
	-----
	|   |
	-----
	|   |
	-----
	|elt|
	-----
	|   |
	-----

	== elt(同一个hash值)
	|name-----|(void *)elt|
	|len
	|value 
*/
void *
ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len)
{
    ngx_uint_t       i;
    ngx_hash_elt_t  *elt;

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "hf:\"%*s\"", len, name);
#endif
	// 根据key值hash找到elt
    elt = hash->buckets[key % hash->size];

    if (elt == NULL) {
        return NULL;
    }

    while (elt->value) {
    	// 判断len是否和elt->len相等
        if (len != (size_t) elt->len) {
            goto next;
        }
		// 判断name是否和elt->name相等
        for (i = 0; i < len; i++) {
            if (name[i] != elt->name[i]) {
                goto next;
            }
        }
		// 相等则返回elt->value
        return elt->value;

    next:
		// 找到下一个elt元素,在name+len之后的void*字节就是
        elt = (ngx_hash_elt_t *) ngx_align_ptr(&elt->name[0] + elt->len,
                                               sizeof(void *));
        continue;
    }
	// 找不到就返回NULL
    return NULL;
}

/*
	前置匹配hash find
*/
void *
ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len)
{
    void        *value;
    ngx_uint_t   i, n, key;

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "wch:\"%*s\"", len, name);
#endif

    n = len;
	// 从后查找到"."的地方,比如: hello.com,匹配hello
    while (n) {
        if (name[n - 1] == '.') {
            break;
        }

        n--;
    }

    key = 0;
	// 从n开始直到len,进行key的计算
    for (i = n; i < len; i++) {
        key = ngx_hash(key, name[i]);
    }

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "key:\"%ui\"", key);
#endif
	// 先从name[n]开始精确匹配
    value = ngx_hash_find(&hwc->hash, key, &name[n], len - n);

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "value:\"%p\"", value);
#endif

    if (value) {

        /*
         * the 2 low bits of value have the special meaning:
         *     00 - value is data pointer for both "example.com"
         *          and "*.example.com";
         *     01 - value is data pointer for "*.example.com" only;
         *     10 - value is pointer to wildcard hash allowing
         *          both "example.com" and "*.example.com";
         *     11 - value is pointer to wildcard hash allowing
         *          "*.example.com" only.
         */
		// 如果为2,wildcard hash
        if ((uintptr_t) value & 2) {
			// 如果n==0,为全匹配,没有模糊匹配
            if (n == 0) {

                /* "example.com" */
				// 11类型,但是没有找到".",直接返回
                if ((uintptr_t) value & 1) {
                    return NULL;
                }
				// 获取ngx_hash_wildcard_t对象
                hwc = (ngx_hash_wildcard_t *)
                                          ((uintptr_t) value & (uintptr_t) ~3);
                return hwc->value;
            }
			// 获取ngx_hash_wildcard_t对象
            hwc = (ngx_hash_wildcard_t *) ((uintptr_t) value & (uintptr_t) ~3);
			// 继续匹配hell(hello偏移一个字符)
            value = ngx_hash_find_wc_head(hwc, name, n - 1);

            if (value) {
                return value;
            }

            return hwc->value;
        }
		// data pointer
        if ((uintptr_t) value & 1) {

            if (n == 0) {

                /* "example.com" */

                return NULL;
            }

            return (void *) ((uintptr_t) value & (uintptr_t) ~3);
        }

        return value;
    }

    return hwc->value;
}

/*
	后缀匹配hash find
*/
void *
ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len)
{
    void        *value;
    ngx_uint_t   i, key;

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "wct:\"%*s\"", len, name);
#endif

    key = 0;
	// 从前开始查找"."的地方,比如:hello.com,匹配com
    for (i = 0; i < len; i++) {
        if (name[i] == '.') {
            break;
        }

        key = ngx_hash(key, name[i]);
    }

    if (i == len) {
        return NULL;
    }

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "key:\"%ui\"", key);
#endif

    value = ngx_hash_find(&hwc->hash, key, name, i);

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "value:\"%p\"", value);
#endif

    if (value) {

        /*
         * the 2 low bits of value have the special meaning:
         *     00 - value is data pointer;
         *     11 - value is pointer to wildcard hash allowing "example.*".
         */
		// 如果为2
        if ((uintptr_t) value & 2) {
			// 偏移下一个字符
            i++;

            hwc = (ngx_hash_wildcard_t *) ((uintptr_t) value & (uintptr_t) ~3);
			// 继续匹配om(com偏移一个字节)
            value = ngx_hash_find_wc_tail(hwc, &name[i], len - i);

            if (value) {
                return value;
            }

            return hwc->value;
        }

        return value;
    }

    return hwc->value;
}


void *
ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key, u_char *name,
    size_t len)
{
    void  *value;

    if (hash->hash.buckets) {
    	// 先进行完全匹配,成功了直接返回
        value = ngx_hash_find(&hash->hash, key, name, len);

        if (value) {
            return value;
        }
    }

    if (len == 0) {
        return NULL;
    }

    if (hash->wc_head && hash->wc_head->hash.buckets) {
    	// 再进行前缀匹配
        value = ngx_hash_find_wc_head(hash->wc_head, name, len);

        if (value) {
            return value;
        }
    }

    if (hash->wc_tail && hash->wc_tail->hash.buckets) {
    	// 进行后缀匹配
        value = ngx_hash_find_wc_tail(hash->wc_tail, name, len);

        if (value) {
            return value;
        }
    }

    return NULL;
}


#define NGX_HASH_ELT_SIZE(name)                                               \
    (sizeof(void *) + ngx_align((name)->key.len + 2, sizeof(void *)))
/*
	hash表初始化
*/
ngx_int_t
ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names, ngx_uint_t nelts)
{
    u_char          *elts;
    size_t           len;
    u_short         *test;
    ngx_uint_t       i, n, key, size, start, bucket_size;
    ngx_hash_elt_t  *elt, **buckets;
	// 判断max_size
    if (hinit->max_size == 0) {
        ngx_log_error(NGX_LOG_EMERG, hinit->pool->log, 0,
                      "could not build %s, you should "
                      "increase %s_max_size: %i",
                      hinit->name, hinit->name, hinit->max_size);
        return NGX_ERROR;
    }
	// 判断bucket_size
    if (hinit->bucket_size > 65536 - ngx_cacheline_size) {
        ngx_log_error(NGX_LOG_EMERG, hinit->pool->log, 0,
                      "could not build %s, too large "
                      "%s_bucket_size: %i",
                      hinit->name, hinit->name, hinit->bucket_size);
        return NGX_ERROR;
    }
	// 循环每个元素
    for (n = 0; n < nelts; n++) {
    	// 小于 sizeof(void*) + ngx_align(name[n]->key.len + 2, sizeof(void*)) + sizeof(void*)
    	// 至少为 3 * sizeof(void *)
        if (hinit->bucket_size < NGX_HASH_ELT_SIZE(&names[n]) + sizeof(void *))
        {
            ngx_log_error(NGX_LOG_EMERG, hinit->pool->log, 0,
                          "could not build %s, you should "
                          "increase %s_bucket_size: %i",
                          hinit->name, hinit->name, hinit->bucket_size);
            return NGX_ERROR;
        }
    }
	// 申请test空间
    test = ngx_alloc(hinit->max_size * sizeof(u_short), hinit->pool->log);
    if (test == NULL) {
        return NGX_ERROR;
    }
	// 计算bucket_size
    bucket_size = hinit->bucket_size - sizeof(void *);
	// 开始地址
    start = nelts / (bucket_size / (2 * sizeof(void *)));
    start = start ? start : 1;
	// 计算开始地址
    if (hinit->max_size > 10000 && nelts && hinit->max_size / nelts < 100) {
        start = hinit->max_size - 1000;
    }
	// 试验性计算
    for (size = start; size <= hinit->max_size; size++) {

        ngx_memzero(test, size * sizeof(u_short));

        for (n = 0; n < nelts; n++) {
            if (names[n].key.data == NULL) {
                continue;
            }
			// 计算key值
            key = names[n].key_hash % size;
            // 计算len大小,len至少为两倍的sizeof(void *)
            len = test[key] + NGX_HASH_ELT_SIZE(&names[n]);

#if 0
            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                          "%ui: %ui %uz \"%V\"",
                          size, key, len, &names[n].key);
#endif
			// 如果大于了bucket_size
            if (len > bucket_size) {
                goto next;
            }
			// len赋值给test[key]
            test[key] = (u_short) len;
        }
		// 如果都处理完了
        goto found;

    next:

        continue;
    }

    size = hinit->max_size;

    ngx_log_error(NGX_LOG_WARN, hinit->pool->log, 0,
                  "could not build optimal %s, you should increase "
                  "either %s_max_size: %i or %s_bucket_size: %i; "
                  "ignoring %s_bucket_size",
                  hinit->name, hinit->name, hinit->max_size,
                  hinit->name, hinit->bucket_size, hinit->name);

found:
	// 确定size后
	// 初始化test[i]大小
    for (i = 0; i < size; i++) {
        test[i] = sizeof(void *);
    }

    for (n = 0; n < nelts; n++) {
        if (names[n].key.data == NULL) {
            continue;
        }
		// 获取到的key
        key = names[n].key_hash % size;
        // len至少为三倍的sizeof(void*)
        len = test[key] + NGX_HASH_ELT_SIZE(&names[n]);

        if (len > 65536 - ngx_cacheline_size) {
            ngx_log_error(NGX_LOG_EMERG, hinit->pool->log, 0,
                          "could not build %s, you should "
                          "increase %s_max_size: %i",
                          hinit->name, hinit->name, hinit->max_size);
            ngx_free(test);
            return NGX_ERROR;
        }

        test[key] = (u_short) len;
    }

    len = 0;

    for (i = 0; i < size; i++) {
    	// 如果test[i]和sizeof(void *)相等则表示还没有hash到,不处理
        if (test[i] == sizeof(void *)) {
            continue;
        }
		// 将test[i]的值对齐到ngx_cacheline_size
        test[i] = (u_short) (ngx_align(test[i], ngx_cacheline_size));
		// len大小进行累加
        len += test[i];
    }
	// 设置hash指针
    if (hinit->hash == NULL) {
    	// size * sizeof(ngx_hash_elt_t *)个节点
        hinit->hash = ngx_pcalloc(hinit->pool, sizeof(ngx_hash_wildcard_t)
                                             + size * sizeof(ngx_hash_elt_t *));
        if (hinit->hash == NULL) {
            ngx_free(test);
            return NGX_ERROR;
        }
		// buckets指针放在hinit->hash + sizeof(ngx_hash_wildcard_t)之后,也就是ngx_hash_wildcard_t放在hinit->hash处
        buckets = (ngx_hash_elt_t **)
                      ((u_char *) hinit->hash + sizeof(ngx_hash_wildcard_t));

    } else {
    	// 如果存在,只需要分配buckets空间
        buckets = ngx_pcalloc(hinit->pool, size * sizeof(ngx_hash_elt_t *));
        if (buckets == NULL) {
            ngx_free(test);
            return NGX_ERROR;
        }
    }
	// 分配elts元素空间
    elts = ngx_palloc(hinit->pool, len + ngx_cacheline_size);
    if (elts == NULL) {
        ngx_free(test);
        return NGX_ERROR;
    }
	// elts向cacheline_size对齐
    elts = ngx_align_ptr(elts, ngx_cacheline_size);

    for (i = 0; i < size; i++) {
        if (test[i] == sizeof(void *)) {
            continue;
        }
		// 将bucket[i]指向elts元素地址
        buckets[i] = (ngx_hash_elt_t *) elts;
        elts += test[i];
    }
	// 清除test[i]的值
    for (i = 0; i < size; i++) {
        test[i] = 0;
    }

    for (n = 0; n < nelts; n++) {
        if (names[n].key.data == NULL) {
            continue;
        }
		// 设置key值
        key = names[n].key_hash % size;
        // 找到对应的elt元素地址
        elt = (ngx_hash_elt_t *) ((u_char *) buckets[key] + test[key]);
		// 设置elt的value值
        elt->value = names[n].value;
        // 设置elt的len大小
        elt->len = (u_short) names[n].key.len;
		// 将key值拷贝到elt->name中
        ngx_strlow(elt->name, names[n].key.data, names[n].key.len);
		// 赋值test[key]的值,这个是再次hash到同一个key,将test[key]赋值
        test[key] = (u_short) (test[key] + NGX_HASH_ELT_SIZE(&names[n]));
    }

    for (i = 0; i < size; i++) {
        if (buckets[i] == NULL) {
            continue;
        }
		// 获取每个elt值
        elt = (ngx_hash_elt_t *) ((u_char *) buckets[i] + test[i]);
		// 将value值赋空
        elt->value = NULL;
    }
	// free(test)
    ngx_free(test);

    hinit->hash->buckets = buckets;
    hinit->hash->size = size;

#if 0

    for (i = 0; i < size; i++) {
        ngx_str_t   val;
        ngx_uint_t  key;

        elt = buckets[i];

        if (elt == NULL) {
            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                          "%ui: NULL", i);
            continue;
        }

        while (elt->value) {
            val.len = elt->len;
            val.data = &elt->name[0];

            key = hinit->key(val.data, val.len);

            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                          "%ui: %p \"%V\" %ui", i, elt, &val, key);

            elt = (ngx_hash_elt_t *) ngx_align_ptr(&elt->name[0] + elt->len,
                                                   sizeof(void *));
        }
    }

#endif

    return NGX_OK;
}

/*
	模糊匹配hash初始化
*/
ngx_int_t
ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts)
{
    size_t                len, dot_len;
    ngx_uint_t            i, n, dot;
    ngx_array_t           curr_names, next_names;
    ngx_hash_key_t       *name, *next_name;
    ngx_hash_init_t       h;
    ngx_hash_wildcard_t  *wdc;
	// 初始化curr_names array, 大小为nelts, 每个元素为ngx_hash_key_t
    if (ngx_array_init(&curr_names, hinit->temp_pool, nelts,
                       sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }
	// 初始化next_names array, 大小为nelts, 每个元素为ngx_hash_key_t
    if (ngx_array_init(&next_names, hinit->temp_pool, nelts,
                       sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    for (n = 0; n < nelts; n = i) {

#if 0
        ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                      "wc0: \"%V\"", &names[n].key);
#endif

        dot = 0;
		// 判断names[n]某个列表中的key是否存在"."
		// 以example.com而言
        for (len = 0; len < names[n].key.len; len++) {
            if (names[n].key.data[len] == '.') {
                dot = 1;
                break;
            }
        }
		// 从curr_names获取一个元素
        name = ngx_array_push(&curr_names);
        if (name == NULL) {
            return NGX_ERROR;
        }
		// 赋值, 就上面的example.com而言, name为example,next_name为com
        name->key.len = len;
        name->key.data = names[n].key.data;
        // hinit->key为key生成函数
        name->key_hash = hinit->key(name->key.data, name->key.len);
        name->value = names[n].value;

#if 0
        ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                      "wc1: \"%V\" %ui", &name->key, dot);
#endif
		// len为 从开始 到 "."之前的长度
        dot_len = len + 1;

        if (dot) {
            len++;
        }

        next_names.nelts = 0;
		// 若原始key的长度和当前计算的长度不相等(也就是存在".")
        if (names[n].key.len != len) {
        	// 需要创建next_name 一个item
        	// 上面的example.com而言, next_name为com
            next_name = ngx_array_push(&next_names);
            if (next_name == NULL) {
                return NGX_ERROR;
            }
            next_name->key.len = names[n].key.len - len;
            next_name->key.data = names[n].key.data + len;
            next_name->key_hash = 0;
            next_name->value = names[n].value;

#if 0
            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                          "wc2: \"%V\"", &next_name->key);
#endif
        }
		// 查询之后的key有没有和前面的相等的
        for (i = n + 1; i < nelts; i++) {
            if (ngx_strncmp(names[n].key.data, names[i].key.data, len) != 0) {
                break;
            }

            if (!dot
                && names[i].key.len > len
                && names[i].key.data[len] != '.')
            {
                break;
            }

            next_name = ngx_array_push(&next_names);
            if (next_name == NULL) {
                return NGX_ERROR;
            }

            next_name->key.len = names[i].key.len - dot_len;
            next_name->key.data = names[i].key.data + dot_len;
            next_name->key_hash = 0;
            next_name->value = names[i].value;

#if 0
            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                          "wc3: \"%V\"", &next_name->key);
#endif
        }
		// 初始化后面的names,所以叫next_names
        if (next_names.nelts) {

            h = *hinit;
            h.hash = NULL;
			// 继续初始化next_names,比如www.example.com.cn,会先初始化为www
            if (ngx_hash_wildcard_init(&h, (ngx_hash_key_t *) next_names.elts,
                                       next_names.nelts)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
			// 转换成wildcard_hash
            wdc = (ngx_hash_wildcard_t *) h.hash;

            if (names[n].key.len == len) {
                wdc->value = names[n].value;
            }
			// 最后两位是2还是3
            name->value = (void *) ((uintptr_t) wdc | (dot ? 3 : 2));

        } else if (dot) {
			// 最后两位为1
            name->value = (void *) ((uintptr_t) name->value | 1);
        }
    }
	// 调用普通hash init
    if (ngx_hash_init(hinit, (ngx_hash_key_t *) curr_names.elts,
                      curr_names.nelts)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
	计算hask_key,算法很简单
*/
ngx_uint_t
ngx_hash_key(u_char *data, size_t len)
{
    ngx_uint_t  i, key;

    key = 0;

    for (i = 0; i < len; i++) {
        key = ngx_hash(key, data[i]);
    }

    return key;
}

/*
	计算hask_key,和ngx_hash_key类似,只是先将每个字符变成小写
*/
ngx_uint_t
ngx_hash_key_lc(u_char *data, size_t len)
{
    ngx_uint_t  i, key;

    key = 0;

    for (i = 0; i < len; i++) {
        key = ngx_hash(key, ngx_tolower(data[i]));
    }

    return key;
}

/*
	计算hash_key,是将src每个字符变成小写之后计算了赋值到dst中
*/
ngx_uint_t
ngx_hash_strlow(u_char *dst, u_char *src, size_t n)
{
    ngx_uint_t  key;

    key = 0;

    while (n--) {
        *dst = ngx_tolower(*src);
        key = ngx_hash(key, *dst);
        dst++;
        src++;
    }

    return key;
}

/*
	keys_array数组初始化
*/
ngx_int_t
ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type)
{
    ngx_uint_t  asize;
	// type=small
    if (type == NGX_HASH_SMALL) {
        asize = 4;
        ha->hsize = 107;

    } else {
    // type=large
        asize = NGX_HASH_LARGE_ASIZE;
        ha->hsize = NGX_HASH_LARGE_HSIZE;
    }
	// 分配keys array内存,分配asize个数,每个元素大小为ngx_hash_key_t
    if (ngx_array_init(&ha->keys, ha->temp_pool, asize, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }
	// 分配dns_wc_head array内存,
    if (ngx_array_init(&ha->dns_wc_head, ha->temp_pool, asize,
                       sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }
	// 分配dns_wc_head array内存,
    if (ngx_array_init(&ha->dns_wc_tail, ha->temp_pool, asize,
                       sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }
	// 申请ha->hsize个ngx_array_t个数组,并初始化为0
    ha->keys_hash = ngx_pcalloc(ha->temp_pool, sizeof(ngx_array_t) * ha->hsize);
    if (ha->keys_hash == NULL) {
        return NGX_ERROR;
    }
	// 申请ha->hsize个ngx_array_t个数组,并初始化为0
    ha->dns_wc_head_hash = ngx_pcalloc(ha->temp_pool,
                                       sizeof(ngx_array_t) * ha->hsize);
    if (ha->dns_wc_head_hash == NULL) {
        return NGX_ERROR;
    }
	// 申请ha->hsize个ngx_array_t个数组,并初始化为0
    ha->dns_wc_tail_hash = ngx_pcalloc(ha->temp_pool,
                                       sizeof(ngx_array_t) * ha->hsize);
    if (ha->dns_wc_tail_hash == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
	加入到hash中,flags代表是否是精确匹配还是模糊匹配
*/
ngx_int_t
ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key, void *value,
    ngx_uint_t flags)
{
    size_t           len;
    u_char          *p;
    ngx_str_t       *name;
    ngx_uint_t       i, k, n, skip, last;
    ngx_array_t     *keys, *hwc;
    ngx_hash_key_t  *hk;

    last = key->len;
	// 如果是模糊匹配
    if (flags & NGX_HASH_WILDCARD_KEY) {

        /*
         * supported wildcards:
         *     "*.example.com", ".example.com", and "www.example.*"
         */

        n = 0;

        for (i = 0; i < key->len; i++) {

            if (key->data[i] == '*') {
            // 首次出现会将n+1, *如果再次出现就会出现问题
                if (++n > 1) {
                    return NGX_DECLINED;
                }
            }
			// 如果出现".."情况
            if (key->data[i] == '.' && key->data[i + 1] == '.') {
                return NGX_DECLINED;
            }
			// 如果达到了"\0"但没到达len大小
            if (key->data[i] == '\0') {
                return NGX_DECLINED;
            }
        }

        /* SKIP值
			0 - 以".*"结尾
			1 - 以"."开头
			2 - 以"*."开头
        */
        
		// 以"."开头
        if (key->len > 1 && key->data[0] == '.') {
            skip = 1;
            goto wildcard;
        }
		// len > 2
        if (key->len > 2) {
			// 以"*."开头
            if (key->data[0] == '*' && key->data[1] == '.') {
                skip = 2;
                goto wildcard;
            }
			// 以".*"结尾
            if (key->data[i - 2] == '.' && key->data[i - 1] == '*') {
                skip = 0;
                last -= 2;
                goto wildcard;
            }
        }
		// 如果*出现了
        if (n) {
            return NGX_DECLINED;
        }
    }

    /* exact hash */
	// 精确匹配
    k = 0;
	// 计算k值
    for (i = 0; i < last; i++) {
        if (!(flags & NGX_HASH_READONLY_KEY)) {
            key->data[i] = ngx_tolower(key->data[i]);
        }
        k = ngx_hash(k, key->data[i]);
    }
	// k继续计算
    k %= ha->hsize;

    /* check conflicts in exact hash */
	// 用k来获取name,ha->keys_hash[k]代表一个ngx_array_t
    name = ha->keys_hash[k].elts;
	// 如果name为空,则重新array_init;如果name不为null,则重新查找
    if (name) {
        for (i = 0; i < ha->keys_hash[k].nelts; i++) {
        	// 如果last != len,长度都不相等,就直接不处理
            if (last != name[i].len) {
                continue;
            }
			// 如果找到了对应的key值,表示已经出现了,不需要处理了
            if (ngx_strncmp(key->data, name[i].data, last) == 0) {
                return NGX_BUSY;
            }
        }

    } else {
    	// 初始化ha->keys_hash[k]这个array节点,ha->keys_hash是hash指针数组
        if (ngx_array_init(&ha->keys_hash[k], ha->temp_pool, 4,
                           sizeof(ngx_str_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }
	// 获取一个ngx_str_t节点
    name = ngx_array_push(&ha->keys_hash[k]);
    if (name == NULL) {
        return NGX_ERROR;
    }

    *name = *key;
	// 获取一个ngx_hash_key_t节点
    hk = ngx_array_push(&ha->keys);
    if (hk == NULL) {
        return NGX_ERROR;
    }
	// 存入ha->keys中
    hk->key = *key;
    // hash值通过计算
    hk->key_hash = ngx_hash_key(key->data, last);
    hk->value = value;

    return NGX_OK;


wildcard:
	// 模糊匹配
    /* wildcard hash */
	// 获取k值
    k = ngx_hash_strlow(&key->data[skip], &key->data[skip], last - skip);
	// 继续计算k值
    k %= ha->hsize;
	 /* SKIP值
		0 - 以".*"结尾
		1 - 以"."开头
		2 - 以"*."开头
    */
    if (skip == 1) {

        /* check conflicts in exact hash for ".example.com" */
		// 获取key的name值
        name = ha->keys_hash[k].elts;
		// 如果name为空,则重新分配
        if (name) {
            len = last - skip;

            for (i = 0; i < ha->keys_hash[k].nelts; i++) {
            	// 如果len不相等,不处理
                if (len != name[i].len) {
                    continue;
                }
				// 如果相等了,直接返回错误
                if (ngx_strncmp(&key->data[1], name[i].data, len) == 0) {
                    return NGX_BUSY;
                }
                // 没有找到对应的元素,直接进行下面的处理
            }

        } else {
        	// 初始化ha->keys_hash[k]这个array节点,ha->keys_hash是hash指针数组
            if (ngx_array_init(&ha->keys_hash[k], ha->temp_pool, 4,
                               sizeof(ngx_str_t))
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }

        name = ngx_array_push(&ha->keys_hash[k]);
        if (name == NULL) {
            return NGX_ERROR;
        }

        name->len = last - 1;
        name->data = ngx_pnalloc(ha->temp_pool, name->len);
        if (name->data == NULL) {
            return NGX_ERROR;
        }
		// 赋值name,skip=1,以"."开头,data[1]去掉"."
        ngx_memcpy(name->data, &key->data[1], name->len);
    }

	/* skip值
		1 - 以"."开头
		2 - 以"*."开头
	*/
	// 以通配符开头的需要转换为后缀样式
    if (skip) {

        /*
         * convert "*.example.com" to "com.example.\0"
         *      and ".example.com" to "com.example\0"
         */
		// 申请内存
        p = ngx_pnalloc(ha->temp_pool, last);
        if (p == NULL) {
            return NGX_ERROR;
        }

        len = 0;
        n = 0;
		// 这里以a.example.com为例子,这里条件是i>0,有点不妥
        for (i = last - 1; i; i--) {
        	// 将a.example.com拷贝到p中为com.example.a
            if (key->data[i] == '.') {
                ngx_memcpy(&p[n], &key->data[i + 1], len);
                n += len;
                p[n++] = '.';
                len = 0;
                continue;
            }
			// len++为.之后的数据(或者从开始的数据)
			// 1. .com
			// 2. a.example.com中的"a"
            len++;
        }
		// 如果还有.之后还有数据直到结束,这里还需要拷贝,比如 a.example.com中的"a"
        if (len) {
            ngx_memcpy(&p[n], &key->data[1], len);
            n += len;
        }
		// 将后面赋值为0
        p[n] = '\0';
		// 头部匹配的hash数组,元素类型为ngx_hash_key_t
        hwc = &ha->dns_wc_head;
        // keys的tail_hash[k]数组,元素类型为ngx_array_t
        keys = &ha->dns_wc_head_hash[k];

    } else {
		// skip=0 以".*"结尾
        /* convert "www.example.*" to "www.example\0" */
		// 整个匹配字符串的长度
        last++;

        p = ngx_pnalloc(ha->temp_pool, last);
        if (p == NULL) {
            return NGX_ERROR;
        }
		// 拷贝到p中
        ngx_cpystrn(p, key->data, last);
		// 尾部匹配hash数组
        hwc = &ha->dns_wc_tail;
        // keys的tail_hash[k]数组
        keys = &ha->dns_wc_tail_hash[k];
    }


    /* check conflicts in wildcard hash */
	// 重新查找name
    name = keys->elts;

    if (name) {
        len = last - skip;

        for (i = 0; i < keys->nelts; i++) {
        	// len不相等,放弃
            if (len != name[i].len) {
                continue;
            }
			// name相等
            if (ngx_strncmp(key->data + skip, name[i].data, len) == 0) {
                return NGX_BUSY;
            }
        }

    } else {
        if (ngx_array_init(keys, ha->temp_pool, 4, sizeof(ngx_str_t)) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    name = ngx_array_push(keys);
    if (name == NULL) {
        return NGX_ERROR;
    }

    name->len = last - skip;
    name->data = ngx_pnalloc(ha->temp_pool, name->len);
    if (name->data == NULL) {
        return NGX_ERROR;
    }
	// 赋值key,这里跳过skip开头的通配符
    ngx_memcpy(name->data, key->data + skip, name->len);


    /* add to wildcard hash */
	// 加入对应的hash中
    hk = ngx_array_push(hwc);
    if (hk == NULL) {
        return NGX_ERROR;
    }

    hk->key.len = last - 1;
    // 这里的key不跳过开头的通配符
    hk->key.data = p;
    // hash值为0
    hk->key_hash = 0;
    // 赋值value
    hk->value = value;
	
    return NGX_OK;
}
