#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "buffer.h"

#define BUF_IMPL_TYPE_MEM 0
#define BUF_IMPL_TYPE_FILE 1

struct buf_node_virtual_func;

struct buf_node_impl_common {
    int impl_type;
    struct buf_node_virtual_func *virtual_fn_ptr;
};

struct buf_node_impl_mem {
    struct buf_node_impl_common common;

    size_t len;
    size_t cap;
    unsigned char *first;
    unsigned char *data;
};

struct buf_node_impl_file {
    struct buf_node_impl_common common;

    size_t len;
    size_t cap;
    int fd;
    size_t offset;
};

union buf_node_virtual {
    struct buf_node_impl_common common;
    struct buf_node_impl_mem mem;
    struct buf_node_impl_file file;
};

struct buf_node {
    struct buf_node *next;
    union buf_node_virtual node_impl;
};

struct buf_s {
    size_t len;
    size_t data_in_file;
    size_t mem_limit;
    size_t file_limit;
    size_t total_limit;
    int file_enable;
    char *file_path;
    struct buf_node *file_node;
    struct buf_node *node_before_file;
    struct buf_node *head;
    struct buf_node *tail;
};

struct buf_node_virtual_func {
    void (*clear)(struct buf_node *n);
    int (*push_data)(struct buf_node *n, unsigned char *data, size_t len,
                     size_t *cnt);
    size_t (*get_cap)(struct buf_node *n);
    size_t (*get_len)(struct buf_node *n);
    size_t (*count_free_cap)(struct buf_node *n);
    void (*set_len)(struct buf_node *n, size_t len);
    void (*add_len)(struct buf_node *n, size_t delta);
    int (*is_full)(struct buf_node *n);
    int (*is_empty)(struct buf_node *n);
    int (*read_from_fd)(struct buf_node *n, int fd, size_t *cnt);
    int (*write_to_fd)(struct buf_node *n, int fd, size_t *cnt);
};

#define BUF_NODE_APPLY(n, fname, ...) \
    (n)->node_impl.common.virtual_fn_ptr->fname(n, ##__VA_ARGS__)
#define BUF_NODE_TYPE(n) (n)->node_impl.common.impl_type

void buf_node_mem_clear(struct buf_node *n);
int buf_node_mem_push_data(struct buf_node *n, unsigned char *data, size_t len,
                           size_t *cnt);
size_t buf_node_mem_get_cap(struct buf_node *n);
size_t buf_node_mem_get_len(struct buf_node *n);
void buf_node_mem_set_len(struct buf_node *n, size_t len);
int buf_node_mem_is_full(struct buf_node *n);
int buf_node_mem_is_empty(struct buf_node *n);
int buf_node_mem_read_from_fd(struct buf_node *n, int fd, size_t *cnt);
size_t buf_node_mem_count_free_cap(struct buf_node *n);
int buf_node_mem_write_to_fd(struct buf_node *n, int fd, size_t *cnt);

struct buf_node_virtual_func buf_node_impl_mem_class = {
    .clear = buf_node_mem_clear,
    .push_data = buf_node_mem_push_data,
    .get_cap = buf_node_mem_get_cap,
    .get_len = buf_node_mem_get_len,
    .add_len = buf_node_mem_set_len,
    .is_full = buf_node_mem_is_full,
    .is_empty = buf_node_mem_is_empty,
    .count_free_cap = buf_node_mem_count_free_cap,
    .read_from_fd = buf_node_mem_read_from_fd,
    .write_to_fd = buf_node_mem_write_to_fd,
};

void buf_node_file_clear(struct buf_node *n);
int buf_node_file_push_data(struct buf_node *n, unsigned char *data, size_t len,
                            size_t *cnt);
size_t buf_node_file_get_cap(struct buf_node *n);
size_t buf_node_file_get_len(struct buf_node *n);
void buf_node_file_set_len(struct buf_node *n, size_t len);
int buf_node_file_is_full(struct buf_node *n);
int buf_node_file_is_empty(struct buf_node *n);
size_t buf_node_file_count_free_cap(struct buf_node *n);

struct buf_node_virtual_func buf_node_impl_file_class = {
    .clear = buf_node_file_clear,
    .push_data = buf_node_file_push_data,
    .get_cap = buf_node_file_get_cap,
    .get_len = buf_node_file_get_len,
    .add_len = buf_node_file_set_len,
    .is_full = buf_node_file_is_full,
    .is_empty = buf_node_file_is_empty,
    .count_free_cap = buf_node_file_count_free_cap,
    .read_from_fd = NULL,
    .write_to_fd = NULL,
};

/* file */

int buf_node_file_init(struct buf_node *n, int fd, size_t cap) {
    if (n == NULL) {
        return -1;
    }
    n->next = NULL;
    n->node_impl.file.fd = fd;
    n->node_impl.file.cap = cap;
    n->node_impl.common.impl_type = BUF_IMPL_TYPE_FILE;
    n->node_impl.common.virtual_fn_ptr = &buf_node_impl_file_class;
    return 0;
}

void buf_node_file_clear(struct buf_node *n) {
    n->node_impl.file.fd = 0;
    n->node_impl.file.len = 0;
    n->node_impl.file.offset = 0;
}

int buf_node_file_get_fd(struct buf_node *n) { return n->node_impl.file.fd; }

size_t buf_node_file_get_cap(struct buf_node *n) {
    return n->node_impl.file.cap;
}

size_t buf_node_file_get_len(struct buf_node *n) {
    return n->node_impl.file.len;
}

size_t buf_node_file_count_free_cap(struct buf_node *n) {
    return n->node_impl.file.cap - n->node_impl.file.len -
           n->node_impl.file.offset;
}

int buf_node_file_is_full(struct buf_node *n) {
    return buf_node_file_count_free_cap(n) <= 0;
}

int buf_node_file_is_empty(struct buf_node *n) {
    return buf_node_file_get_len(n) <= 0;
}

void buf_node_file_set_len(struct buf_node *n, size_t len) {
    n->node_impl.file.len = len;
}

int buf_node_file_write_to_fd(struct buf_node *n, int fd, size_t *cnt) {
    return -1;
}

/* mem */

int buf_node_file_push_data(struct buf_node *n, unsigned char *data, size_t len,
                            size_t *cnt) {
    if (data == NULL || len < 0) {
        return -1;
    }
    int r = write(buf_node_file_get_fd(n), data, len);
    if (r < 0) {
        if (errno == EAGAIN || errno == EINTR) {
            return BUF_EAGAIN;
        } else {
            return BUF_ERR;
        }
    } else {
        *cnt = r;
        n->node_impl.file.len += r;
    }

    return 0;
}

int buf_node_mem_init(struct buf_node *n, size_t cap) {
    if (n == NULL) {
        return -1;
    }
    void *data = malloc(cap);
    if (data == NULL) {
        return BUF_EOM;
    }
    n->next = NULL;
    n->node_impl.common.virtual_fn_ptr = &buf_node_impl_mem_class;
    n->node_impl.common = BUF_IMPL_TYPE_MEM;
    n->node_impl.mem.data = (unsigned char *)data;
    n->node_impl.mem.cap = cap;
    n->node_impl.mem.len = 0;
    n->node_impl.mem.first = (unsigned char *)data;
    return 0;
}

int buf_node_mem_init_with_data(struct buf_node *n, unsigned char *data,
                                size_t len) {
    if (data == NULL || len == 0) {
        return -1;
    }
    if (buf_node_mem_init(n, len) < 0) {
        return -1;
    }

    unsigned char *dest = n->node_impl.mem.data;
    while (len--) {
        *dest++ = *data++;
    }
    n->node_impl.mem.len = len;
    n->node_impl.mem.first = n->node_impl.mem.data;

    return 0;
}

void buf_node_mem_clear(struct buf_node *n) {
    free(n->node_impl.mem.data);
    n->node_impl.mem.data = NULL;
    n->node_impl.mem.len = 0;
    n->node_impl.mem.cap = 0;
    n->node_impl.mem.first = NULL;
}

int buf_node_mem_push_data(struct buf_node *n, unsigned char *data, size_t len,
                           size_t *cnt) {
    if (data == NULL || len < 0) {
        return -1;
    }

    unsigned char **ppdata = &n->node_impl.mem.data;
    if (*ppdata == NULL) {
        *ppdata = (unsigned char *)malloc(len);
        if (*ppdata == NULL) {
            return BUF_EOM;
        }
        n->node_impl.mem.cap = len;
        n->node_impl.mem.first = *ppdata;
    }

    size_t cap = n->node_impl.mem.cap;
    unsigned char *p = n->node_impl.mem.first;
    unsigned char *end = n->node_impl.mem.data + cap;

    int copied = 0;
    while (p < end && copied < len) {
        copied++;
        *p++ = *data++;
    }
    *cnt = copied;

    return 0;
}

size_t buf_node_mem_get_cap(struct buf_node *n) { return n->node_impl.mem.cap; }

size_t buf_node_mem_get_len(struct buf_node *n) { return n->node_impl.mem.len; }

size_t buf_node_mem_count_free_cap(struct buf_node *n) {
    return (n->node_impl.mem.data + n->node_impl.mem.cap) -
           (n->node_impl.mem.first + n->node_impl.mem.len);
}

int buf_node_mem_is_full(struct buf_node *n) {
    return buf_node_mem_count_free_cap(n) <= 0;
}

int buf_node_mem_is_empty(struct buf_node *n) {
    return buf_node_mem_get_len(n) <= 0;
}

void buf_node_mem_set_len(struct buf_node *n, size_t len) {
    n->node_impl.mem.len = len;
}

int buf_node_mem_read_from_fd(struct buf_node *n, int fd, size_t *cnt) {
    unsigned char *p = n->node_impl.mem.first + n->node_impl.mem.len;
    unsigned char *end = n->node_impl.mem.data + n->node_impl.mem.cap;
    size_t len = end - p;

    int r = read(fd, p, len);
    if (r > 0) {
        buf_node_mem_set_len(n, buf_node_mem_get_len(n) + r);
        *cnt = r;
        return 0;
    } else if (r == 0) {
        *cnt = 0;
        return BUF_EOF;
    } else {
        if (errno == EAGAIN || errno == EINTR) {
            return BUF_EAGAIN;
        } else {
            return -1;
        }
    }
}

int buf_node_mem_write_to_fd(struct buf_node *n, int fd, size_t *cnt) {
    unsigned char *p = n->node_impl.mem.first;
    size_t len = buf_node_mem_get_len(n);
    *cnt = 0;
    int r = write(fd, p, len);
    if (r > 0) {
        *cnt += r;
        len -= r;
        buf_node_mem_set_len(n, len);
    } else {
        if (errno == EAGAIN || errno == EINTR) {
            return BUF_EAGAIN;
        } else {
            return BUF_ERR;
        }
    }
    return BUF_OK;
}

/* buf_t */

int buf_init(buf_t *b) {
    if (b == NULL) {
        return -1;
    }
    b->head = NULL;
    b->tail = NULL;
    b->data_in_file = 0;
    b->mem_limit = BUF_DEFAULT_MAX_MEM;
    b->total_limit = BUF_DEFAULT_MAX_MEM;
    b->file_enable = BUF_DEFAULT_ENABLE_FILE;
    b->file_limit = BUF_DEFAULT_MAX_FILE_SIZE;
    b->file_path = NULL;
    b->len = 0;
    b->file_node = NULL;
    b->node_before_file = NULL;

    return 0;
}

int buf_init_with_initial_cap(buf_t *b, size_t cap) {
    if (buf_init(b) < 0) {
        return -1;
    }
    struct buf_node *n = (struct buf_node *)malloc(sizeof(struct buf_node));
    if (buf_node_mem_init(n, cap) < 0) {
        free(n);
        return -1;
    }

    b->head = n;
    b->tail = n;

    return 0;
}

void buf_set_max_size(buf_t *b, size_t limit) { b->total_limit = limit; }

void buf_set_mem_limit(buf_t *b, size_t limit) { b->mem_limit = limit; }

void buf_set_max_file_size(buf_t *b, size_t limit) { b->file_limit = limit; }

void buf_enable_file(buf_t *b, int enable, char *path) {
    b->file_enable = enable;
    b->file_path = path;
}

int buf_add_node(buf_t *b, struct buf_node *n) {
    if (b == NULL || n == NULL) {
        return -1;
    }

    if (b->tail == NULL) {
        b->head = n;
    } else {
        b->tail->next = n;
    }
    b->tail = n;
    b->len += n->node_impl.mem.len;

    return 0;
}

int buf_create_file_node(buf_t *b) {
    int fd = open(b->file_path, O_RDWR | O_CREAT | O_NONBLOCK);
    if (fd < 0) {
        return BUF_ERR;
    }

    struct buf_node *n = (struct buf_node *)malloc(sizeof(struct buf_node));
    if (n == NULL) {
        return BUF_EOM;
    }
    buf_node_file_init(n, fd, b->file_limit);
    n->next = b->head;
    b->head = n;
    if (b->tail == NULL) {
        b->tail = b->head;
    }
    b->file_node = n;
    return 0;
}

int buf_to_file(buf_t *b) {
    struct buf_node *file_node = NULL;

    if (b->file_node == NULL) {
        int r = buf_create_file_node(b);
        if (r < 0) {
            return r;
        }
    }
    file_node = b->file_node;

    struct buf_node **next = &file_node->next;
    while (file_node && *next) {
        if (BUF_NODE_APPLY(*next, get_len)) {
            size_t cnt;
            int r = BUF_NODE_APPLY(file_node, push_data,
                                   (*next)->node_impl.mem.first,
                                   (*next)->node_impl.mem.len, &cnt);
            if (r == BUF_OK) {
                b->data_in_file -= cnt;
                size_t left = BUF_NODE_APPLY(*next, get_len) - cnt;
                if (left == 0) {
                    struct buf_node *t = *next;
                    *next = (*next)->next;
                    BUF_NODE_APPLY(t, clear);
                    free(t);
                }
            } else {
                if (errno == EAGAIN || errno == EINTR) {
                    return BUF_EAGAIN;
                }
            }
        }
    }
    if (file_node->next == NULL) {
        b->tail = file_node;
    }

    return 0;
}

int buf_remove_file_node(buf_t *b) {
    struct buf_node *file_node = b->file_node;
    if (b->node_before_file == NULL) {
        b->head = file_node->next;
    } else {
        b->node_before_file->next = file_node->next;
    }

    close(file_node->node_impl.file.fd);
    BUF_NODE_APPLY(file_node, clear);
    free(file_node);
    unlink(b->file_path);
    b->data_in_file = 0;
    b->file_node = NULL;
    b->node_before_file = NULL;

    return 0;
}

int buf_has_file(buf_t *b) { return b->file_node != NULL; }

int buf_add_new_node_before_file(buf_t *b, size_t cap) {
    if (b->len - b->data_in_file >= b->mem_limit) {
        return BUF_LIMIT;
    }
    size_t left_mem = b->mem_limit - b->len + b->data_in_file;
    if (cap > left_mem) {
        cap = left_mem;
    }

    struct buf_node *dest_node =
        (struct buf_node *)malloc(sizeof(struct buf_node));
    if (dest_node == NULL) {
        return BUF_EOM;
    }
    int r = buf_node_mem_init(dest_node, cap);
    if (r < 0) {
        return r;
    }

    dest_node->next = b->file_node;
    if (b->node_before_file) {
        b->node_before_file->next = dest_node;
    }
    b->node_before_file = dest_node;

    return 0;
}

int buf_file_to_mem(buf_t *b) {
    if (b->data_in_file == 0) {
        return buf_remove_file_node(b);
    }

    if (b->node_before_file == NULL ||
        BUF_NODE_APPLY(b->node_before_file, is_full)) {
        int r = buf_add_new_node_before_file(b, 4000);
        if (r < 0) {
            return r;
        }
    }

    struct buf_node *dest_node = b->node_before_file;

    size_t cnt;
    int r = BUF_NODE_APPLY(dest_node, read_from_fd,
                           b->file_node->node_impl.file.fd, &cnt);
    if (r < 0) {
        return r;
    }

    b->data_in_file -= cnt;
    if (b->data_in_file == 0) {
        return buf_remove_file_node(b);
    }

    return 0;
}

int buf_limit_exceed(buf_t *b, size_t len) {
    if (!b->file_enable) {
        return b->len + len - b->data_in_file >= b->mem_limit;
    } else {
        return b->len + len > b->total_limit;
    }
}

size_t buf_count_free_space(buf_t *b) {
    if (b->file_enable) {
        return b->total_limit - b->len;
    }
}

int buf_push_data_new_node(buf_t *b, unsigned char *data, size_t len) {
    struct buf_node *n = (struct buf_node *)malloc(sizeof(struct buf_node));
    if (buf_node_mem_init_with_data(n, data, len) < 0) {
        return -1;
    }
    if (buf_add_node(b, n) < 0) {
        BUF_NODE_APPLY(n, clear);
        return -1;
    }

    return 0;
}

int buf_push_back_data(buf_t *b, unsigned char *data, size_t len) {
    if (buf_limit_exceed(b, len)) {
        return BUF_LIMIT;
    }

    if (b->tail == NULL || BUF_NODE_APPLY(b->tail, is_full) ||
        BUF_NODE_TYPE(b->tail) == BUF_IMPL_TYPE_FILE) {
        if (buf_push_data_new_node(b, data, len) < 0) {
            return -1;
        }
    } else {
        size_t cnt;
        int r = BUF_NODE_APPLY(b->tail, push_data, data, len, &cnt);
        if (r < 0) {
            return -1;
        }
        if (cnt < len) {
            if (buf_push_data_new_node(b, data + cnt, len - cnt) < 0) {
                return -1;
            }
        }
    }

    if (b->len - b->data_in_file >= b->mem_limit) {
        return buf_to_file(b);
    }

    return 0;
}

int buf_read_from_fd(buf_t *b, int fd, size_t *cnt) {
    size_t buf_cap = 1500;
    size_t tmp = 0;
    *cnt = 0;

    while (1) {
        if (b->tail == NULL || BUF_NODE_APPLY(b->tail, is_full) ||
            BUF_NODE_TYPE(b->tail) == BUF_IMPL_TYPE_FILE) {
            struct buf_node *n =
                (struct buf_node *)malloc(sizeof(struct buf_node));
            if (n == NULL) {
                return BUF_EOM;
            }
            if (buf_limit_exceed(b, buf_cap)) {
                buf_cap = buf_count_free_space(b);
            }
            if (buf_node_mem_init(n, buf_cap) < 0) {
                return BUF_EOM;
            }
        }
        int r = BUF_NODE_APPLY(b->tail, read_from_fd, fd, &tmp);
        *cnt += tmp;
        if (r != BUF_OK) {
            return r;
        }

        if (buf_limit_exceed(b, 0)) {
            return 0;
        }
    }

    return 0;
}

int buf_write_to_fd(buf_t *b, int fd, size_t *cnt) {
    struct buf_node *n = b->head;
    struct buf_node *tmpn = NULL;
    size_t tmp;
    while (n) {
        if (BUF_NODE_TYPE(n) == BUF_IMPL_TYPE_FILE) {
            int r = buf_file_to_mem(b);
            if (r < 0) {
                return r;
            }
        }

        b->head = n;
        if (BUF_NODE_APPLY(n, is_empty)) {
            tmpn = n;
            n = n->next;
            BUF_NODE_APPLY(tmpn, clear);
            free(tmpn);
            continue;
        }

        int r = BUF_NODE_APPLY(n, write_to_fd, fd, &tmp);
        b->len -= tmp;
        *cnt += tmp;
        if (r != BUF_OK) {
            return r;
        }

        if (BUF_NODE_APPLY(n, is_empty)) {
            tmpn = n;
            n = n->next;
            BUF_NODE_APPLY(tmpn, clear);
            free(tmpn);
            continue;
        }
    }
    b->len = 0;
    b->head = b->tail = NULL;

    return BUF_OK;
}
