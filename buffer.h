#ifndef QL_BUFFER_H_
#define QL_BUFFER_H_

#define BUF_OK 0
#define BUF_ERR -1
#define BUF_EOF -77
#define BUF_EAGAIN -79
#define BUF_EAGAIN2 -80
#define BUF_EOM -70
#define BUF_LIMIT -71


#define BUF_DEFAULT_MAX_SIZE 5000000000
#define BUF_DEFAULT_MAX_MEM 100000000
#define BUF_DEFAULT_MAX_FILE_SIZE 5000000000
#define BUF_DEFAULT_ENABLE_FILE 0

struct buf_s;
typedef struct buf_s buf_t;


#endif /* QL_BUFFER_H_ */
