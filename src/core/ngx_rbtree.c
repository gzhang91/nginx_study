
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * The red-black tree code is based on the algorithm described in
 * the "Introduction to Algorithms" by Cormen, Leiserson and Rivest.
 */


static ngx_inline void ngx_rbtree_left_rotate(ngx_rbtree_node_t **root,
    ngx_rbtree_node_t *sentinel, ngx_rbtree_node_t *node);
static ngx_inline void ngx_rbtree_right_rotate(ngx_rbtree_node_t **root,
    ngx_rbtree_node_t *sentinel, ngx_rbtree_node_t *node);


void
ngx_rbtree_insert(ngx_rbtree_t *tree, ngx_rbtree_node_t *node)
{
    ngx_rbtree_node_t  **root, *temp, *sentinel;

    /* a binary tree insert */
	// 使用&表示要更改root的内容
    root = &tree->root;
    sentinel = tree->sentinel;
	// 如果为空,表示没有元素,直接插入
    if (*root == sentinel) {
        node->parent = NULL;
        // 设置left和right都为sentinel
        node->left = sentinel;
        node->right = sentinel;
        // 设置为黑
        ngx_rbt_black(node);
        // 根节点赋值
        *root = node;

        return;
    }
	// 调用insert函数插入, 插入的节点的颜色为红色
    tree->insert(*root, node, sentinel);

    /* re-balance tree */
	// 出现父节点和node都为红的情况, 采用从下到上的调整
    while (node != *root && ngx_rbt_is_red(node->parent)) {
		// 左边是RED情况
        if (node->parent == node->parent->parent->left) {
            temp = node->parent->parent->right;
			// 如果node->parent->parent->right为红,不需要更新,只需要涂色即可
            if (ngx_rbt_is_red(temp)) {
                ngx_rbt_black(node->parent);
                ngx_rbt_black(temp);
                ngx_rbt_red(node->parent->parent);
                node = node->parent->parent;

            } else {
            	// parent为左子树, node为右子树,这种情况需要两次旋转
                if (node == node->parent->right) {
                    node = node->parent;
                    ngx_rbtree_left_rotate(root, sentinel, node);
                }
				// parent为左子树, node也为左子树,这种情况只需要一次旋转
                ngx_rbt_black(node->parent);
                ngx_rbt_red(node->parent->parent);
                ngx_rbtree_right_rotate(root, sentinel, node->parent->parent);
            }

        } else {
        // 右边是RED情况
            temp = node->parent->parent->left;
			// 如果temp节点为红色,不需要更新,只需直接涂色即可
            if (ngx_rbt_is_red(temp)) {
                ngx_rbt_black(node->parent);
                ngx_rbt_black(temp);
                ngx_rbt_red(node->parent->parent);
                node = node->parent->parent;

            } else {
                if (node == node->parent->left) {
                    node = node->parent;
                    ngx_rbtree_right_rotate(root, sentinel, node);
                }

                ngx_rbt_black(node->parent);
                ngx_rbt_red(node->parent->parent);
                ngx_rbtree_left_rotate(root, sentinel, node->parent->parent);
            }
        }
    }
	// 头节点必须为黑色
    ngx_rbt_black(*root);
}

/*
	默认提供的insert函数
*/
void
ngx_rbtree_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t  **p;

    for ( ;; ) {

        p = (node->key < temp->key) ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    // 设置parent
    node->parent = temp;
    // left,right都为sentinel
    node->left = sentinel;
    node->right = sentinel;
    // 设置为red
    ngx_rbt_red(node);
}

/*
	insert timer的默认函数
*/
void
ngx_rbtree_insert_timer_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t  **p;

    for ( ;; ) {

        /*
         * Timer values
         * 1) are spread in small range, usually several minutes,
         * 2) and overflow each 49 days, if milliseconds are stored in 32 bits.
         * The comparison takes into account that overflow.
         */

        /*  node->key < temp->key */

        p = ((ngx_rbtree_key_int_t) (node->key - temp->key) < 0)
            ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


void
ngx_rbtree_delete(ngx_rbtree_t *tree, ngx_rbtree_node_t *node)
{
    ngx_uint_t           red;
    ngx_rbtree_node_t  **root, *sentinel, *subst, *temp, *w;

    /* a binary tree delete */
    // 从175行到201行,表示找到subst
	// 获取root根节点
    root = &tree->root;
    // 获取sentinel节点
    sentinel = tree->sentinel;
	// 如果左子树为空
    if (node->left == sentinel) {
        temp = node->right;
        subst = node;

    } else if (node->right == sentinel) {
    // 如果右子树为空
        temp = node->left;
        subst = node;

    } else {
    // 左右子树不为空
    	// 找到右子树中最左边(最小)的节点, 也可以查找左子树的最右(最大)的节点
        subst = ngx_rbtree_min(node->right, sentinel);
		// 这里应该直接是temp=subst->right吧,一直左偏(作者这里的意思可能就没有按上面的ngx_rbtree_min/max来特定化,
		//	而是两种情况都考虑了)
        if (subst->left != sentinel) {
            temp = subst->left;
        } else {
            temp = subst->right;
        }
    }

    // 从当前行到274行为与备选节点进行替换赋值等操作
	// 针对从根开始的左子树为空或者右子树为空或者左右子树都为空的情况
    if (subst == *root) {
    	// 直接进行偏移
        *root = temp;
        // 将根节点必须设置为黑节点
        ngx_rbt_black(temp);

        /* DEBUG stuff */
        node->left = NULL;
        node->right = NULL;
        node->parent = NULL;
        node->key = 0;

        return;
    }
	// 获取subst的颜色
    red = ngx_rbt_is_red(subst);
    // 这里保存subst(取代节点)的下继子树,subst的下继子树只能是一个单边的(要么左子树,要么右子树,不可能两者都是)
	// subst为左子树
    if (subst == subst->parent->left) {
    	// 将subst摘下来,并将temp保存到原来subst的地方
        subst->parent->left = temp;

    } else {
    // subst为右子树
    	// 将subst摘下来,并将temp保存到原来subst的地方
        subst->parent->right = temp;
    }
	// 对于叶子节点或者存在单个子节点的父节点
    if (subst == node) {
        temp->parent = subst->parent;

    } else {
		// 对于subst->parent==node的情况下,这里表示只能是node的右子树节点就是subst,而且subst左右子树为空
        if (subst->parent == node) {
            temp->parent = subst;

        } else {
            temp->parent = subst->parent;
        }
		// 开始赋值,将node->left赋值给subst->left
        subst->left = node->left;
        // 因为上面已经将subst的右子树挂接到parent上了,这里可以直接赋值
        subst->right = node->right;
        // 将parent也拷贝
        subst->parent = node->parent;
        // 颜色也拷贝
        ngx_rbt_copy_color(subst, node);
		// 如果是root节点,将root重新赋值
        if (node == *root) {
            *root = subst;

        } else {
        	// 设置父指针
            if (node == node->parent->left) {
                node->parent->left = subst;
            } else {
                node->parent->right = subst;
            }
        }
		// 设置原来node的左右子树的parent
        if (subst->left != sentinel) {
            subst->left->parent = subst;
        }

        if (subst->right != sentinel) {
            subst->right->parent = subst;
        }
    }

    /* DEBUG stuff */
    node->left = NULL;
    node->right = NULL;
    node->parent = NULL;
    node->key = 0;
	// 如果为红色节点,直接返回该节点
    if (red) {
        return;
    }

    /* a delete fixup */
    // 从此行开始, 表示进行delete的层级(可能)更新操作
	// temp是最底层影响的节点,从底层到上一直更新
    while (temp != *root && ngx_rbt_is_black(temp)) {
	// temp为parent的左子树
        if (temp == temp->parent->left) {
        	// 获取右子树
            w = temp->parent->right;

            if (ngx_rbt_is_red(w)) {
                ngx_rbt_black(w);
                ngx_rbt_red(temp->parent);
                ngx_rbtree_left_rotate(root, sentinel, temp->parent);
                w = temp->parent->right;
            }
			// 如果w的左右都为黑色,涂色即可
            if (ngx_rbt_is_black(w->left) && ngx_rbt_is_black(w->right)) {
                ngx_rbt_red(w);
                temp = temp->parent;

            } else {
            // 不都是黑色
            	// 
                if (ngx_rbt_is_black(w->right)) {
                    ngx_rbt_black(w->left);
                    ngx_rbt_red(w);
                    ngx_rbtree_right_rotate(root, sentinel, w);
                    w = temp->parent->right;
                }

                ngx_rbt_copy_color(w, temp->parent);
                ngx_rbt_black(temp->parent);
                ngx_rbt_black(w->right);
                ngx_rbtree_left_rotate(root, sentinel, temp->parent);
                temp = *root;
            }

        } else {
		// temp为parent的右子树
			// 获取左子树 
            w = temp->parent->left;

            if (ngx_rbt_is_red(w)) {
                ngx_rbt_black(w);
                ngx_rbt_red(temp->parent);
                ngx_rbtree_right_rotate(root, sentinel, temp->parent);
                w = temp->parent->left;
            }
			// 左右子树都为黑色,涂色即可
            if (ngx_rbt_is_black(w->left) && ngx_rbt_is_black(w->right)) {
                ngx_rbt_red(w);
                temp = temp->parent;

            } else {
            // 不都为黑色
                if (ngx_rbt_is_black(w->left)) {
                    ngx_rbt_black(w->right);
                    ngx_rbt_red(w);
                    ngx_rbtree_left_rotate(root, sentinel, w);
                    w = temp->parent->left;
                }

                ngx_rbt_copy_color(w, temp->parent);
                ngx_rbt_black(temp->parent);
                ngx_rbt_black(w->left);
                ngx_rbtree_right_rotate(root, sentinel, temp->parent);
                temp = *root;
            }
        }
    }

    ngx_rbt_black(temp);
}


static ngx_inline void
ngx_rbtree_left_rotate(ngx_rbtree_node_t **root, ngx_rbtree_node_t *sentinel,
    ngx_rbtree_node_t *node)
{
    ngx_rbtree_node_t  *temp;

    temp = node->right;
    node->right = temp->left;
	// 设置temp->left的父节点为node,因为需要左转
    if (temp->left != sentinel) {
        temp->left->parent = node;
    }
	// 设置temp的父节点为node的父节点
    temp->parent = node->parent;
	// 如果node为root节点,需要重新赋值
    if (node == *root) {
        *root = temp;

    } else if (node == node->parent->left) {
    // 如果node为父节点的左节点,设置父节点的左子树指向temp
        node->parent->left = temp;

    } else {
    // 否则设置node父节点右子树指向temp
        node->parent->right = temp;
    }
	// 将temp->left指向node
    temp->left = node;
    // node的父节点指向temp
    node->parent = temp;
}

/*
	右旋转
*/
static ngx_inline void
ngx_rbtree_right_rotate(ngx_rbtree_node_t **root, ngx_rbtree_node_t *sentinel,
    ngx_rbtree_node_t *node)
{
    ngx_rbtree_node_t  *temp;
	// left子树
    temp = node->left;
    // node的左子树指向temp的右子树
    node->left = temp->right;
	// 设置temp->right的父节点为node
    if (temp->right != sentinel) {
        temp->right->parent = node;
    }
	// 设置temp的父节点为原来node的父节点
    temp->parent = node->parent;
	// 如果node为root,需要更新
    if (node == *root) {
        *root = temp;

    } else if (node == node->parent->right) {
    // 如果node为右子树节点,将right指向temp
        node->parent->right = temp;

    } else {
    // 否则为左子树节点,将left指向temp
        node->parent->left = temp;
    }
	// temp的右子树为node
    temp->right = node;
    // node的parent为temp
    node->parent = temp;
}

/*
	从tree中获取node的下一个节点
*/
ngx_rbtree_node_t *
ngx_rbtree_next(ngx_rbtree_t *tree, ngx_rbtree_node_t *node)
{
    ngx_rbtree_node_t  *root, *sentinel, *parent;

    sentinel = tree->sentinel;

    if (node->right != sentinel) {
    	// 获取右子树中最小的节点
        return ngx_rbtree_min(node->right, sentinel);
    }
	// 获取root节点
    root = tree->root;

    for ( ;; ) {
    	// 获取node的parent
        parent = node->parent;
		// 如果node是root,直接返回,没有下一个节点
		// 因为此时root没有右节点, 代表没有右子树,到这里为止,已经访问完毕了
        if (node == root) {
            return NULL;
        }
		// 如果node为parent->left,表示parent还没有访问,直接返回parent
        if (node == parent->left) {
            return parent;
        }
		// 向上溯源
        node = parent;
    }
}
