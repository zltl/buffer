#ifndef QL_BUFFER_H_
#define QL_BUFFER_H_

#define BUF_OK 0
#define BUF_ERR -1
#define BUF_EOF -77
#define BUF_EAGAIN -79
#define BUF_EOM -70
#define BUF_LIMIT -71

#define BUF_DEFAULT_MAX_SIZE 40000000

#define BUF_NODE_DEFAULT_SIZE 4096

struct buf_s;
typedef struct buf_s buf_t;

int buf_init(buf_t *b);
int buf_init_with_initial_cap(buf_t *b, size_t cap);
void buf_node_clear(buf_t *b);
void buf_set_max_size(buf_t *b, size_t limit);
int buf_push_back_data(buf_t *b, unsigned char *data, size_t len);
int buf_read_from_fd(buf_t *b, int fd, size_t *cnt);
int buf_write_to_fd(buf_t *b, int fd, size_t *cnt);

#endif /* QL_BUFFER_H_ */
