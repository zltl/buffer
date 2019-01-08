#ifndef HG_BUFFER_H_
#define HG_BUFFER_H_

#include <stdlib.h>
#include <openssl/ssl.h>

#define BUF_OK 0
#define BUF_ERR -1
#define BUF_EOF -77
#define BUF_EAGAIN -79
#define BUF_EOM -70
#define BUF_LIMIT -71

#define BUF_DEFAULT_MAX_SIZE (1<<29) // 512 mib

#define BUF_NODE_DEFAULT_SIZE 4096

struct buf_node;

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
    int (*write_to_ssl)(struct buf_node *n, SSL *ssl, size_t *cnt);
};

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

union buf_node_virtual {
    struct buf_node_impl_common common;
    struct buf_node_impl_mem mem;
};

struct buf_node {
    struct buf_node *next;
    union buf_node_virtual node_impl;
};

struct buf_s {
    size_t len;
    size_t total_limit;
    struct buf_node *head;
    struct buf_node *tail;
};

struct buf_s;
typedef struct buf_s buf_t;

int buf_init(buf_t *b);
int buf_init_with_initial_cap(buf_t *b, size_t cap);
void buf_set_max_size(buf_t *b, size_t limit);
int buf_push_back_data(buf_t *b, unsigned char *data, size_t len);
int buf_read_from_fd(buf_t *b, int fd, size_t *cnt);
int buf_write_to_fd(buf_t *b, int fd, size_t *cnt);
int buf_write_to_ssl(buf_t *b, SSL *ssl, size_t *cnt);
size_t buf_get_len(buf_t *b);
void buf_clear(buf_t *b);

#define BUF_NODE_APPLY(n, fname, ...) \
    (n)->node_impl.common.virtual_fn_ptr->fname(n, ##__VA_ARGS__)
#define BUF_NODE_TYPE(n) (n)->node_impl.common.impl_type

#endif /* HG_BUFFER_H_ */
