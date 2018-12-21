#include <errno.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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
    int fd;
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
    n->node_impl.common.virtual_fn_ptr->fname(n, ##__VA_ARGS__)
#define BUF_NODE_TYPE(n) n->node_impl.common.impl_type

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
    b->total_limit = BUF_DEFAULT_MAX_SIZE;
    b->file_enable = BUF_DEFAULT_ENABLE_FILE;
    b->file_limit = BUF_DEFAULT_MAX_FILE_SIZE;
    b->file_path = NULL;
    b->len = 0;
    b->fd = -1;

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

int buf_write_to_file(buf_t *b) {
    if (b->fd == -1) {

    }
}

int buf_can_push(buf_t *b, size_t len) {
    // TODO
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

int buf_push_data(buf_t *b, unsigned char *data, size_t len) {
    if (b->tail == NULL || BUF_NODE_APPLY(b->tail, is_full) ||
        BUF_NODE_TYPE(b->tail) == BUF_IMPL_TYPE_FILE) {
        if (buf_push_data_new_node(b, data, len) < 0) {
            return -1;
        }
    } else {
        int cnt;
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
    return 0;
}

/*
  try read from fd begen with cap of 1500 bytes, if still have data in
  system cache, enlarge the cap by 1.5, till EGAIN
 */
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
            if (buf_node_mem_init(n, buf_cap) < 0) {
                return BUF_EOM;
            }
        }
        int r = BUF_NODE_APPLY(b->tail, read_from_fd, fd, &tmp);
        *cnt += tmp;
        if (r != BUF_OK) {
            return r;
        }
    }
}

int buf_write_to_fd(buf_t *b, int fd, size_t *cnt) {
    struct buf_node *n = b->head;
    struct buf_node *tmpn = NULL;
    size_t tmp;
    while (n) {
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
