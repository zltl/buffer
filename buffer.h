#ifndef QL_BUFFER_H_
#define QL_BUFFER_H_

#define BUF_OK 0
#define BUF_ERR -1
#define BUF_EOF -77
#define BUF_EAGAIN -79
#define BUF_EOM -70
#define BUF_LIMIT -71

#define BUF_DEFAULT_MAX_SIZE 5000000000
#define BUF_DEFAULT_MAX_MEM 100000000
#define BUF_DEFAULT_MAX_FILE_SIZE 5000000000
#define BUF_DEFAULT_ENABLE_FILE 0

#define BUF_NODE_DEFAULT_CAP 4000

struct buf_s;
typedef struct buf_s buf_t;

int buf_init(buf_t *b);
int buf_init_with_initial_cap(buf_t *b, size_t cap);
void buf_set_max_size(buf_t *b, size_t limit);
void buf_set_mem_limit(buf_t *b, size_t limit);
void buf_set_max_file_size(buf_t *b, size_t limit);
void buf_enable_file(buf_t *b, int enable, char *path);
int buf_push_back_data(buf_t *b, unsigned char *data, size_t len);
int buf_read_from_fd(buf_t *b, int fd, size_t *cnt);
int buf_write_to_fd(buf_t *b, int fd, size_t *cnt);

#endif /* QL_BUFFER_H_ */
