#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "buffer.h"

#define BUF_IMPL_TYPE_MEM 0

/* mem node */

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
int buf_node_mem_write_to_ssl(struct buf_node *n, SSL *ssl, size_t *cnt);

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
    .write_to_ssl = buf_node_mem_write_to_ssl,
};

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
    n->node_impl.common.impl_type = BUF_IMPL_TYPE_MEM;
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

    int r = buf_node_mem_init(n, len);
    if (r < 0) {
        return r;
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
    if (n->node_impl.mem.data) {
        free(n->node_impl.mem.data);
        n->node_impl.mem.data = NULL;
    }
    n->node_impl.mem.len = 0;
    n->node_impl.mem.cap = 0;
    n->node_impl.mem.first = NULL;
}

int buf_node_mem_push_data(struct buf_node *n, unsigned char *data, size_t len,
                           size_t *cnt) {
    *cnt = 0;

    if (data == NULL || len < 0) {
        return -1;
    }

    unsigned char **ppdata = &n->node_impl.mem.data;
    if (*ppdata == NULL) {
        *ppdata = (unsigned char *)malloc(len);
        if (*ppdata == NULL) {
            return BUF_EOM;
        }
        n->node_impl.mem.len = 0;
        n->node_impl.mem.cap = len;
        n->node_impl.mem.first = *ppdata;
    }

    size_t cap = n->node_impl.mem.cap;
    unsigned char *p = n->node_impl.mem.first + n->node_impl.mem.len;
    unsigned char *end = n->node_impl.mem.data + cap;

    size_t copied = 0;
    while (p < end && copied < len) {
        copied++;
        *p++ = *data++;
    }
    *cnt = copied;
    n->node_impl.mem.len += copied;

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

// write and drop datas
int buf_node_mem_write_to_fd(struct buf_node *n, int fd, size_t *cnt) {
    unsigned char *p = n->node_impl.mem.first;
    size_t len = buf_node_mem_get_len(n);
    *cnt = 0;
    int r = write(fd, p, len);
    if (r > 0) {
        *cnt += r;
        len -= r;
        n->node_impl.mem.first += r;
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

int buf_node_mem_write_to_ssl(struct buf_node *n, SSL *ssl, size_t *cnt) {
    unsigned char *p = n->node_impl.mem.first;
    size_t len = buf_node_mem_get_len(n);
    *cnt = 0;
    int r = SSL_write(ssl, p, len);
    if (r > 0) {
        *cnt += r;
        len -= r;
        n->node_impl.mem.first += r;
        buf_node_mem_set_len(n, len);
    } else {
        int err = SSL_get_error(ssl, r);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
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
    b->total_limit = BUF_DEFAULT_MAX_SIZE;
    b->len = 0;

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

int buf_add_node(buf_t *b, struct buf_node *n) {
    if (b->tail == NULL) {
        b->head = n;
    } else {
        b->tail->next = n;
    }
    b->tail = n;
    b->len += n->node_impl.mem.len;

    return 0;
}

void buf_clear(buf_t *b) {
    struct buf_node **pn = &b->head;
    while (*pn) {
        struct buf_node *t = *pn;
        *pn = t->next;
        BUF_NODE_APPLY(t, clear);
        free(t);
    }
    b->len = 0;
    b->head = b->tail = NULL;
}

int buf_limit_exceed(buf_t *b, size_t len) {
    return b->len + len > b->total_limit;
}

size_t buf_count_free_space(buf_t *b) { return b->total_limit - b->len; }

size_t buf_get_len(buf_t *b) { return b->len; }

int buf_push_data_new_node(buf_t *b, unsigned char *data, size_t len) {
    if (buf_limit_exceed(b, len)) {
        return BUF_LIMIT;
    }

    size_t cap = b->len >> 1;  // cap = len * 0.5
    if (cap < len) {
        cap = len;
    }
    if (buf_limit_exceed(b, cap)) {
        cap = buf_count_free_space(b);
    }

    struct buf_node *n = (struct buf_node *)malloc(sizeof(struct buf_node));
    if (buf_node_mem_init(n, cap) < 0) {
        free(n);
        return BUF_EOM;
    }

    if (buf_add_node(b, n) < 0) {
        BUF_NODE_APPLY(n, clear);
        free(n);
        return -1;
    }
    size_t cnt;
    BUF_NODE_APPLY(b->tail, push_data, data, len, &cnt);
    b->len += cnt;

    return 0;
}

int buf_push_back_data(buf_t *b, unsigned char *data, size_t len) {
    if (buf_limit_exceed(b, len)) {
        return BUF_LIMIT;
    }

    if (b->tail == NULL || BUF_NODE_APPLY(b->tail, is_full)) {
        int r = buf_push_data_new_node(b, data, len);
        if (r < 0) {
            return r;
        }
    } else {
        size_t cnt;
        int r = BUF_NODE_APPLY(b->tail, push_data, data, len, &cnt);
        if (r < 0) {
            return r;
        }
        b->len += cnt;
        if (cnt < len) {
            r = buf_push_data_new_node(b, data + cnt, len - cnt);
            if (r < 0) {
                return r;
            }
            b->len += len - cnt;
        }
    }

    return 0;
}

int buf_read_from_fd(buf_t *b, int fd, size_t *cnt) {
    size_t buf_cap = BUF_NODE_DEFAULT_SIZE;
    size_t tmp = 0;
    *cnt = 0;

    while (1) {
        if (buf_limit_exceed(b, 1)) {
            return BUF_EOM;
        }

        if (b->tail == NULL || BUF_NODE_APPLY(b->tail, is_full)) {
            struct buf_node *n =
                (struct buf_node *)malloc(sizeof(struct buf_node));
            if (n == NULL) {
                return BUF_EOM;
            }
            if (buf_limit_exceed(b, buf_cap)) {
                buf_cap = buf_count_free_space(b);
            }
            if (buf_node_mem_init(n, buf_cap) < 0) {
                free(n);
                return BUF_EOM;
            }
            buf_add_node(b, n);
        }
        int r = BUF_NODE_APPLY(b->tail, read_from_fd, fd, &tmp);
        *cnt += tmp;
        if (r != BUF_OK) {
            return r;
        }
        b->len += tmp;
    }

    return 0;
}

// dest type = 0 for fd, 1 for ssl
int buf_write(buf_t *b, void *dest, int dest_type, size_t *cnt) {
    struct buf_node *n = b->head;
    struct buf_node *tmpn = NULL;
    size_t tmp;
    *cnt = 0;

    while (n) {
        b->head = n;
        if (BUF_NODE_APPLY(n, is_empty)) {
            tmpn = n;
            n = n->next;
            BUF_NODE_APPLY(tmpn, clear);
            free(tmpn);
            continue;
        }

        int r = 0;
        if (dest_type == 0) {
            r = BUF_NODE_APPLY(n, write_to_fd, *(int *)dest, &tmp);
        } else if (dest_type == 1) {
            r = BUF_NODE_APPLY(n, write_to_ssl, (SSL *)dest, &tmp);
        } else {
            return BUF_ERR;
        }

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

// write data into fd, then drop datas have been wrote
int buf_write_to_fd(buf_t *b, int fd, size_t *cnt) {
    return buf_write(b, &fd, 0, cnt);
}

int buf_write_to_ssl(buf_t *b, SSL *ssl, size_t *cnt) {
    return buf_write(b, ssl, 1, cnt);
}
