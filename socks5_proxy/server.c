#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdbool.h>

#define BUFFER_SIZE 65536
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define IP_SIZE 4
#define MAX_BLACKLIST 100

enum socks {
    VERSION5 = 0x05
};

enum socks5_auth_methods {
    METHOD_NO_AUTHENTICATION = 0x00,
};

enum socks5_command {
    CONNECT = 0x01,
    BIND = 0x02,
    UDP_ASSOCIATE = 0x03,
};

enum socks5_address_type {
    IPV4 = 0x01,
    DOMAINNAME = 0x03,
    IPV6 = 0x04,
};

enum socks5_reply_status {
    SUCCEEDED = 0x00,
    GENERAL_FAILURE = 0x01,
    CONNECTION_NOT_ALLOWED = 0x02,
    NETWORK_UNREACHABLE = 0x03,
    HOST_UNREACHABLE = 0x04,
    CONNECTION_REFUSED = 0x05,
    TTL_EXPIRED = 0x06,
    COMMAND_NOT_SUPPORTED = 0x07,
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08,
};

FILE *log_file = NULL;
pthread_mutex_t lock;
int deamon_mode = 0;
int auth_type;
unsigned short int port = 1080;

typedef struct {
    in_addr_t ip;     // IP dạng network byte order (vd: 8.8.8.8 -> 0x08080808)
    unsigned short port; 
} blacklist_t;

blacklist_t blacklist_items[MAX_BLACKLIST];
int blacklist_count = 0;

/* Hàm log */
void log_message(const char *message, ...);

/* Hàm đọc và ghi đủ n byte (hoặc gặp lỗi/dừng) */
int readn(int fd, void *buffer, int n);
int writen(int fd, const void *buffer, int n);

/* Các hàm tiện ích */
void thread_exit(int ret, int fd);
int socks5_handshake(int fd, int *version);
int socks5_no_auth(int fd);
void socks5_auth(int fd, int methods_count);
void socks5_auth_not_supported(int fd);

/* Tách CMD và ATYP ra khỏi header 4 byte */
int socks5_command(int fd, unsigned char *cmd, unsigned char *atyp);

int socks5_connect(int type, void *buffer, unsigned short int portnum);
unsigned short int socks5_read_port(int fd);
char *socks5_ip_read(int fd);
void socks5_ip_write(int fd, const char *ip, unsigned short int port);
char *socks5_domain_read(int fd, unsigned char *size);
void socks5_domain_write(int fd, const char *domain, unsigned char size, unsigned short int port);
void socket_pipe(int fd0, int fd1);
void *thread_process(void *fd);
void app_loop();
void deamonize();
void usage(char *app);
void load_blacklist(const char *filename);
bool is_blacklisted(in_addr_t ip, unsigned short port);

/* Hỗ trợ UDP Associate */
void socks5_handle_udp_associate(int client_fd, unsigned char atyp);

int main(int argc, char *argv[]) {
    int ret;
    log_file = stdout;
    auth_type = METHOD_NO_AUTHENTICATION;

    pthread_mutex_init(&lock, NULL);
    signal(SIGPIPE, SIG_IGN);

    while ((ret = getopt(argc, argv, "n:l:hd")) != -1) {
        switch (ret) {
            case 'd':
                deamon_mode = 1;
                deamonize();
                break;
            case 'n':
                port = (unsigned short)(atoi(optarg) & 0xFFFF);
                break;
            case 'l': {
                FILE *fp = freopen(optarg, "wa", log_file);
                if (fp) {
                    log_file = fp;
                } else {
                    fprintf(stderr, "Could not open log file: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            }
            case 'h':
            default:
                usage(argv[0]);
                break;
        }
    }

    log_message("Starting N8NET SOCKS5 proxy server on port %d", port);
    load_blacklist("blacklist.txt");
    app_loop();

    pthread_mutex_destroy(&lock);
    if (log_file && log_file != stdout) {
        fclose(log_file);
    }
    return 0;
}

/* Đọc đủ n byte, hoặc gặp EOF/lỗi thì dừng. 
 * Trả về số byte thực tế đọc được (có thể < n nếu EOF). 
 * Trả về -1 nếu có lỗi không khắc phục được. */
int readn(int fd, void *buffer, int n) {
    int nleft = n;
    int nread;
    char *ptr = (char *)buffer;

    while (nleft > 0) {
        nread = read(fd, ptr, nleft);
        if (nread < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue; 
            }
            return -1;  /* Lỗi thật sự */
        } else if (nread == 0) {
            break;      /* Hết dữ liệu (EOF) */
        }
        nleft -= nread;
        ptr += nread;
    }
    return (n - nleft); /* Số byte thực sự đọc được */
}

/* Ghi đủ n byte, hoặc gặp lỗi thì dừng.
 * Trả về số byte thực tế ghi được; -1 nếu gặp lỗi không khắc phục được. */
int writen(int fd, const void *buffer, int n) {
    int nleft = n;
    int nwritten;
    const char *ptr = (const char *)buffer;

    while (nleft > 0) {
        nwritten = write(fd, ptr, nleft);
        if (nwritten <= 0) {
            if (nwritten < 0 && (errno == EINTR || errno == EAGAIN)) {
                continue;
            }
            return -1; /* Lỗi */
        }
        nleft -= nwritten;
        ptr += nwritten;
    }
    return (n - nleft);
}

/* In ra log (nếu không chạy daemon). */
void log_message(const char *message, ...) {
    if (deamon_mode) {
        return;  /* Trong mode daemon, tạm thời không ghi log ra stdout */
    }

    char vbuffer[512];
    va_list args;
    va_start(args, message);
    vsnprintf(vbuffer, ARRAY_SIZE(vbuffer), message, args);
    va_end(args);

    time_t now;
    time(&now);

    char *date = ctime(&now);
    /* ctime() trả về chuỗi có \n ở cuối, xóa nó đi */
    date[strlen(date) - 1] = '\0';

    pthread_t self = pthread_self();
    pthread_mutex_lock(&lock);
    if (errno != 0) {
        fprintf(log_file, "[%s] [%lu] Critical: %s - %s\n", 
                date, (unsigned long)self, vbuffer, strerror(errno));
        errno = 0;
    } else {
        fprintf(log_file, "[%s] [%lu] Info: %s\n", 
                date, (unsigned long)self, vbuffer);
    }
    fflush(log_file);
    pthread_mutex_unlock(&lock);
}

/* Hướng dẫn sử dụng */
void usage(char *app) {
    printf("USAGE: %s [-n PORT] [-l LOGFILE] [-d]\n", app);
    printf("N8NET SOCKS5 proxy server (NO AUTHENTICATION). Default port: 1080\n");
    exit(1);
}

/* Thoát luồng an toàn */
void thread_exit(int ret, int fd) {
    close(fd);
    /* Không trả về địa chỉ của biến cục bộ. Ta ép sang (void*) kiểu số nguyên. */
    pthread_exit((void *)(intptr_t)ret);
}

/* Vòng lặp chính: Lắng nghe và accept */
void app_loop() {
    int sock_fd, net_fd;
    int optval = 1;
    struct sockaddr_in local, remote;
    socklen_t remotelen;

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        log_message("Failed to create socket");
        exit(1);
    }

    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        log_message("Failed to set SO_REUSEADDR");
        exit(1);
    }

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);

    if (bind(sock_fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        log_message("Failed to bind socket");
        exit(1);
    }

    if (listen(sock_fd, 25) < 0) {
        log_message("Failed to listen on socket");
        exit(1);
    }

    remotelen = sizeof(remote);
    memset(&remote, 0, sizeof(remote));

    log_message("Listening on port %d ...", port);

    while (1) {
        if ((net_fd = accept(sock_fd, (struct sockaddr *)&remote, &remotelen)) < 0) {
            log_message("Failed to accept connection");
            exit(1);
        }

        /* Thiết lập TCP_NODELAY cho socket kết nối thực tế */
        setsockopt(net_fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));

        pthread_t worker;
        int *pnet_fd = (int *)malloc(sizeof(int));
        if (!pnet_fd) {
            log_message("Failed to allocate memory for thread arg");
            close(net_fd);
            continue;
        }
        *pnet_fd = net_fd;

        if (pthread_create(&worker, NULL, &thread_process, (void *)pnet_fd) != 0) {
            log_message("Failed to create thread");
            free(pnet_fd);
            close(net_fd);
            exit(1);
        } else {
            pthread_detach(worker);
        }
    }
}

/* Hàm xử lý mỗi kết nối */
void *thread_process(void *fd) {
    int net_fd = *(int *)fd;
    free(fd);  /* Giải phóng vùng nhớ tạm */
    int version = 0;
    int inet_fd = -1;

    int methods_count = socks5_handshake(net_fd, &version);
    if (version != VERSION5) {
        thread_exit(1, net_fd);
    }

    /* Xác thực (hiện chỉ hỗ trợ NO_AUTHENTICATION) */
    socks5_auth(net_fd, methods_count);

    /* Lấy CMD và ATYP */
    unsigned char cmd, atyp;
    if (socks5_command(net_fd, &cmd, &atyp) < 0) {
        thread_exit(1, net_fd);
    }

    /* Xử lý theo CMD */
    switch (cmd) {
    case CONNECT: {
        /* Xử lý CONNECT */
        if (atyp == IPV4) {
            char *ip = socks5_ip_read(net_fd);
            if (!ip) {
                thread_exit(1, net_fd);
            }
            unsigned short p = socks5_read_port(net_fd);

            inet_fd = socks5_connect(IPV4, ip, ntohs(p));
            if (inet_fd == -1) {
                free(ip);
                thread_exit(1, net_fd);
            }
            socks5_ip_write(net_fd, ip, p);
            free(ip);
        } else if (atyp == DOMAINNAME) {
            unsigned char size;
            char *domain = socks5_domain_read(net_fd, &size);
            if (!domain) {
                thread_exit(1, net_fd);
            }
            unsigned short p = socks5_read_port(net_fd);

            inet_fd = socks5_connect(DOMAINNAME, domain, ntohs(p));
            if (inet_fd == -1) {
                free(domain);
                thread_exit(1, net_fd);
            }
            socks5_domain_write(net_fd, domain, size, p);
            free(domain);
        } else {
            /* Không hỗ trợ IPV6, ... */
            thread_exit(1, net_fd);
        }

        /* Chuyển tiếp dữ liệu hai chiều */
        socket_pipe(inet_fd, net_fd);
        close(inet_fd);
        thread_exit(0, net_fd);
        break;
    }

    case UDP_ASSOCIATE: {
        /* Xử lý lệnh UDP Associate */
        socks5_handle_udp_associate(net_fd, atyp);
        thread_exit(0, net_fd);
        break;
    }

    default:
        log_message("Unsupported CMD = %d", cmd);
        // Có thể phản hồi lỗi COMMAND_NOT_SUPPORTED rồi thread_exit.
        thread_exit(1, net_fd);
        break;
    }

    return NULL; // never reached
}

/* Đọc 2 byte đầu và trả về số methods, đồng thời gán version */
int socks5_handshake(int fd, int *version) {
    char init[2];
    int nread = readn(fd, init, 2);
    if (nread < 2) {
        log_message("Invalid SOCKS handshake (not enough bytes)");
        thread_exit(0, fd);
    }

    if (init[0] != VERSION5) {
        log_message("Invalid SOCKS version: %hhX", init[0]);
        thread_exit(0, fd);
    }

    log_message("SOCKS handshake: VER=%hhX, NMETHODS=%hhX", init[0], init[1]);
    *version = init[0];
    return (unsigned char)init[1];
}

/* Phản hồi NO_AUTH */
int socks5_no_auth(int fd) {
    char response[2] = { (char)VERSION5, (char)METHOD_NO_AUTHENTICATION };
    if (writen(fd, response, 2) < 0) {
        return -1;
    }
    return 0;
}

/* Tách lấy CMD và ATYP từ 4 byte (VER, CMD, RSV, ATYP) */
int socks5_command(int fd, unsigned char *cmd, unsigned char *atyp) {
    char header[4];
    int nread = readn(fd, header, 4);
    if (nread < 4) {
        log_message("Invalid SOCKS command header");
        return -1;
    }
    log_message("Command: VER=%hhX CMD=%hhX RSV=%hhX ATYP=%hhX",
                header[0], header[1], header[2], header[3]);

    /* Kiểm tra header[0] == VERSION5 */
    *cmd = (unsigned char)header[1];
    *atyp = (unsigned char)header[3];
    return 0;
}

/* Đọc port 2 byte */
unsigned short int socks5_read_port(int fd) {
    unsigned short int p;
    int nread = readn(fd, &p, sizeof(p));
    if (nread < (int)sizeof(p)) {
        log_message("Failed to read port");
        return 0;
    }
    log_message("Port %hu", ntohs(p));
    return p;
}

/* Đọc 4 byte IP */
char *socks5_ip_read(int fd) {
    char *ip = (char *)malloc(IP_SIZE);
    if (!ip) return NULL;

    int nread = readn(fd, ip, IP_SIZE);
    if (nread < IP_SIZE) {
        log_message("Failed to read IPv4 address");
        free(ip);
        return NULL;
    }
    log_message("IP %hhu.%hhu.%hhu.%hhu", 
                (unsigned char)ip[0], (unsigned char)ip[1], 
                (unsigned char)ip[2], (unsigned char)ip[3]);
    return ip;
}

/* Gửi lại phản hồi CONNECT thành công với ATYP=IPV4 */
void socks5_ip_write(int fd, const char *ip, unsigned short int port) {
    char response[4] = { (char)VERSION5, (char)SUCCEEDED, 0x00, (char)IPV4 };
    /* Ghi 4 byte header */
    if (writen(fd, response, 4) < 0) return;
    /* Ghi 4 byte địa chỉ IP */
    if (writen(fd, ip, IP_SIZE) < 0) return;
    /* Ghi 2 byte port */
    if (writen(fd, &port, sizeof(port)) < 0) return;
}

/* Đọc độ dài domain (1 byte), sau đó đọc domain */
char *socks5_domain_read(int fd, unsigned char *size) {
    unsigned char s;
    if (readn(fd, &s, 1) < 1) {
        log_message("Failed to read domain size");
        return NULL;
    }

    char *address = (char *)malloc(s + 1);
    if (!address) {
        return NULL;
    }
    address[s] = '\0';

    if (readn(fd, address, s) < (int)s) {
        log_message("Failed to read domain name");
        free(address);
        return NULL;
    }

    log_message("Domain: %s", address);
    *size = s;
    return address;
}

/* Gửi lại phản hồi CONNECT thành công với ATYP=DOMAINNAME */
void socks5_domain_write(int fd, const char *domain, unsigned char size, unsigned short int port) {
    char response[4] = { (char)VERSION5, (char)SUCCEEDED, 0x00, (char)DOMAINNAME };
    if (writen(fd, response, 4) < 0) return;
    if (writen(fd, &size, 1) < 0) return;
    if (writen(fd, domain, size) < 0) return;
    if (writen(fd, &port, sizeof(port)) < 0) return;
}

/* Kết nối giữa hai socket (TCP) theo kiểu forward data */
void socket_pipe(int fd0, int fd1) {
    int maxfd = (fd0 > fd1) ? fd0 : fd1;
    fd_set rd_set;
    char buffer_r[BUFFER_SIZE];

    log_message("Piping data between two sockets...");
    while (1) {
        FD_ZERO(&rd_set);
        FD_SET(fd0, &rd_set);
        FD_SET(fd1, &rd_set);

        int ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        if (FD_ISSET(fd0, &rd_set)) {
            ssize_t nread = recv(fd0, buffer_r, BUFFER_SIZE, 0);
            if (nread <= 0) {
                break;
            }
            send(fd1, buffer_r, nread, 0);
        }

        if (FD_ISSET(fd1, &rd_set)) {
            ssize_t nread = recv(fd1, buffer_r, BUFFER_SIZE, 0);
            if (nread <= 0) {
                break;
            }
            send(fd0, buffer_r, nread, 0);
        }
    }
    log_message("Socket pipe end");
}

/* Xác thực SOCKS5 (tối giản: chỉ NO_AUTH) */
void socks5_auth(int fd, int methods_count) {
    int supported = 0;
    for (int i = 0; i < methods_count; i++) {
        char type;
        if (readn(fd, &type, 1) < 1) {
            log_message("Failed to read auth method");
            thread_exit(1, fd);
        }
        log_message("Method AUTH %hhX", type);
        if (type == auth_type) {
            supported = 1;
        }
    }

    if (!supported) {
        socks5_auth_not_supported(fd);
        thread_exit(1, fd);
    }

    int ret = 0;
    switch(auth_type) {
        case METHOD_NO_AUTHENTICATION:
            ret = socks5_no_auth(fd);
            break;
        default:
            ret = -1;
            break;
    }

    if (ret != 0) {
        thread_exit(1, fd);
    }
}

/* Phản hồi không hỗ trợ method nào */
void socks5_auth_not_supported(int fd) {
    char response[2] = { (char)VERSION5, (char)0xFF };
    writen(fd, response, 2);
}

/* Kết nối đến server đích (IP hoặc DOMAINNAME) */
int socks5_connect(int type, void *buf, unsigned short int portnum) {
    int fd;
    if (type == IPV4) {
        struct sockaddr_in remote;
        char *ip = (char *)buf;

        memset(&remote, 0, sizeof(remote));
        remote.sin_family = AF_INET;
        remote.sin_port = htons(portnum);
        memcpy(&remote.sin_addr.s_addr, ip, 4);

        // === BLACKLIST CHECK ===
        if (is_blacklisted(remote.sin_addr.s_addr, remote.sin_port)) {
            log_message("Blocked attempt to connect BLACKLISTED IP %s:%d", inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));
            return -1;
        }

        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            log_message("Failed to create socket for remote");
            return -1;
        }
        if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
            log_message("Failed to connect to remote server (IPv4)");
            close(fd);
            return -1;
        }
        return fd;
    }
    else if (type == DOMAINNAME) {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_UNSPEC;   /* IPv4 hoặc IPv6 */
        hints.ai_socktype = SOCK_STREAM;

        char portaddr[6];
        snprintf(portaddr, sizeof(portaddr), "%u", portnum);

        log_message("Resolving domain %s:%s", (char *)buf, portaddr);
        int ret = getaddrinfo((char *)buf, portaddr, &hints, &res);
        if (ret != 0) {
            log_message("getaddrinfo failed: %s", gai_strerror(ret));
            return -1;
        }

        struct addrinfo *rp;
        for (rp = res; rp != NULL; rp = rp->ai_next) {
            fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd == -1) {
                continue;
            }

            // Check blacklist (chỉ áp dụng cho IPv4)
            if (rp->ai_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in*)rp->ai_addr;
                // Lưu ý port => rp->ai_addr không nhất thiết = portnum ?
                sin->sin_port = htons(portnum);

                if (is_blacklisted(sin->sin_addr.s_addr, sin->sin_port)) {
                    log_message("Blocked attempt to connect BLACKLISTED domain->IP %s:%d", inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
                    close(fd);
                    continue; // thử IP kế tiếp
                };
            }

            if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
                /* Kết nối thành công */
                freeaddrinfo(res);
                return fd;
            }
            close(fd);
        }
        freeaddrinfo(res);
        log_message("Failed to connect to remote server (DOMAINNAME)");
        return -1;
    }
    return -1;
}

/* Chế độ daemon */
void deamonize() {
    pid_t pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    /* Thoát tiến trình cha */
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    /* Tạo session mới */
    if (setsid() < 0) {
        exit(EXIT_FAILURE);
    }

    /* Bỏ qua SIGHUP, SIGCHLD */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    /* fork() lần 2 để đảm bảo không thể mở terminal */
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    /* Đảm bảo quyền cho các file/directory được tạo ra */
    umask(0);
    chdir("/");

    /* Đóng toàn bộ file descriptor cũ */
    long maxfd = sysconf(_SC_OPEN_MAX);
    for (int x = 0; x < maxfd; x++) {
        close(x);
    }
}

/* ===========  HÀM QUAN TRỌNG: Xử lý UDP Associate  =========== */
static void *udp_relay_thread(void *arg);

/* Dữ liệu cần cho luồng UDP relay */
typedef struct {
    int udp_fd;        // Socket UDP proxy đang lắng nghe
    struct sockaddr_in client_addr; // Địa chỉ client (nếu cần)
} udp_relay_ctx_t;

/*
 * socks5_handle_udp_associate:
 * - Đọc địa chỉ mà client yêu cầu (IP hoặc Domain) + port (nếu có).
 * - Tạo 1 UDP socket cục bộ, bind 1 cổng random.
 * - Gửi lại địa chỉ (BND.ADDR, BND.PORT) cho client.
 * - Tạo luồng relay UDP (nếu muốn chạy song song).
 */
void socks5_handle_udp_associate(int client_fd, unsigned char atyp) {
    unsigned short dest_port = 0;
    char *dest_ip_or_domain = NULL;
    unsigned char size = 0;

    /* 1) Đọc địa chỉ đích (client “gợi ý”), thực ra UDP Associate cho phép 0 */
    if (atyp == IPV4) {
        dest_ip_or_domain = socks5_ip_read(client_fd);
        if (!dest_ip_or_domain) {
            thread_exit(1, client_fd);
        }
        dest_port = socks5_read_port(client_fd);

        log_message("UDP_ASSOCIATE with dest = %hhu.%hhu.%hhu.%hhu:%hu",
                    (unsigned char)dest_ip_or_domain[0],
                    (unsigned char)dest_ip_or_domain[1],
                    (unsigned char)dest_ip_or_domain[2],
                    (unsigned char)dest_ip_or_domain[3],
                    ntohs(dest_port));

    } else if (atyp == DOMAINNAME) {
        dest_ip_or_domain = socks5_domain_read(client_fd, &size);
        if (!dest_ip_or_domain) {
            thread_exit(1, client_fd);
        }
        dest_port = socks5_read_port(client_fd);
        log_message("UDP_ASSOCIATE with domain = %s, port = %hu",
                    dest_ip_or_domain, ntohs(dest_port));
    } else {
        /* IPv6 chưa hỗ trợ ở đây */
        thread_exit(1, client_fd);
    }

    /* 2) Tạo UDP socket cục bộ */
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) {
        log_message("Failed to create UDP socket");
        free(dest_ip_or_domain);
        thread_exit(1, client_fd);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY); 
    addr.sin_port = 0; /* để hệ thống tự cấp cổng trống */

    if (bind(udp_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_message("Failed to bind UDP socket");
        close(udp_fd);
        free(dest_ip_or_domain);
        thread_exit(1, client_fd);
    }

    /* Lấy cổng thực sự đã bind */
    socklen_t len = sizeof(addr);
    if (getsockname(udp_fd, (struct sockaddr *)&addr, &len) < 0) {
        log_message("getsockname failed");
        close(udp_fd);
        free(dest_ip_or_domain);
        thread_exit(1, client_fd);
    }
    unsigned short local_port = addr.sin_port; // đang dạng network byte order

    /* 3) Gửi lại thông tin (BND.ADDR, BND.PORT) cho client */
    {
        char rep[4] = { VERSION5, SUCCEEDED, 0x00, IPV4 };
        if (writen(client_fd, rep, 4) < 0) goto udp_associate_fail;

        /* Giả sử trả về 0.0.0.0 (hoặc bind_ip thật) */
        unsigned char bind_ip[4] = {0,0,0,0};
        if (writen(client_fd, bind_ip, 4) < 0) goto udp_associate_fail;

        if (writen(client_fd, &local_port, 2) < 0) goto udp_associate_fail;
    }

    log_message("UDP Associate established on port %hu (host order: %d)",
                ntohs(local_port), ntohs(local_port));

    /* 4) Tạo luồng relay nếu muốn. Ở đây mình tạo 1 luồng để proxy data UDP. */
    udp_relay_ctx_t *ctx = (udp_relay_ctx_t *)malloc(sizeof(*ctx));
    if (!ctx) {
        goto udp_associate_fail;
    }
    ctx->udp_fd = udp_fd;
    /* Trong trường hợp muốn biết client_addr, ta lấy từ getsockname(client_fd) hoặc remote... */

    pthread_t tid;
    if (pthread_create(&tid, NULL, udp_relay_thread, ctx) != 0) {
        log_message("Failed to create udp_relay_thread");
        free(ctx);
        goto udp_associate_fail;
    }
    pthread_detach(tid);

    /* Giải phóng tạm IP/Domain */
    free(dest_ip_or_domain);
    return;

udp_associate_fail:
    close(udp_fd);
    free(dest_ip_or_domain);
    thread_exit(1, client_fd);
}

/*
 * udp_relay_thread: Vòng lặp nhận gói UDP từ client (qua udp_fd), 
 * parse SOCKS5 UDP HEADER => gửi đi server đích.
 * Cũng nhận gói từ server đích => đóng gói header SOCKS5 => gửi client.
 *
 * Ở đây minh họa tối giản => do code thực tế sẽ phức tạp (cần parse FRAG, ATYP, DST, v.v.)
 */
static void *udp_relay_thread(void *arg) {
    udp_relay_ctx_t *ctx = (udp_relay_ctx_t *)arg;
    int udp_fd = ctx->udp_fd;
    free(ctx);

    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    struct sockaddr_in to_addr;
    memset(&to_addr, 0, sizeof(to_addr));
    to_addr.sin_family = AF_INET;

    char buf[BUFFER_SIZE];

    log_message("UDP relay thread started.");

    /* Vòng lặp “vô tận” chờ client gửi gói UDP vào */
    while (1) {
        ssize_t n = recvfrom(udp_fd, buf, BUFFER_SIZE, 0,
                             (struct sockaddr *)&from_addr, &from_len);
        if (n <= 0) {
            if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
                continue;
            }
            break;
        }

        /* parse SOCKS5 UDP header (theo RFC 1928):
         *  +----+----+----+----+----+----+----+----+
         *  |RSV | RSV| FRAG | ATYP | DST.ADDR | DST.PORT | DATA |
         *   2     2     1      1      ?          2       ...
         * Thật ra RFC nói RSV = 2 byte (0x00 0x00), 
         * ta thường thấy: [0x00, 0x00], FRAG=0, ATYP=1/3/4, ...
         */
        if (n < 4) { /* gói quá nhỏ */
            continue;
        }
        unsigned char *p = (unsigned char *)buf;
        // p[0..1] = RSV=0x00, p[2] = FRAG=0x00 (thường), p[3] = ATYP
        // parse ...
        unsigned char frag = p[2];
        unsigned char atyp = p[3];
        if (frag != 0) {
            // FRAG != 0 => cần ghép mảnh, code demo không làm
            continue;
        }
        int idx = 4; // Bắt đầu DST.ADDR

        // Giả sử ATYP=1 => IPv4, =3 => Domain, =4 => IPv6
        // Ở demo, chỉ xử lý IPv4:
        if (atyp == IPV4) {
            if (n < idx + 4 + 2) {
                // Chưa đủ 4 byte IP + 2 byte port
                continue;
            }
            unsigned char dst_ip[4];
            memcpy(dst_ip, &p[idx], 4);
            idx += 4;
            unsigned short dst_port;
            memcpy(&dst_port, &p[idx], 2);
            idx += 2;

            // Dữ liệu thật
            int data_len = n - idx;
            unsigned char *udp_data = &p[idx];

            // Tạo to_addr
            to_addr.sin_addr.s_addr = *(uint32_t *)(dst_ip);
            to_addr.sin_port = dst_port;

            /* Gửi data tới server đích */
            sendto(udp_fd, udp_data, data_len, 0,
                   (struct sockaddr *)&to_addr, sizeof(to_addr));
        }
        else if (atyp == DOMAINNAME) {
            // parse domain ...
            // Tương tự, code demo lược bỏ.
        }
        else if (atyp == IPV6) {
            // parse IPv6 ...
            // Lược bỏ
        }
    }

    close(udp_fd);
    log_message("UDP relay thread end.");
    pthread_exit(NULL);
}

void load_blacklist(const char *filename) {
    FILE *fp = fopen(filename, "r");

    if (!fp) {
        // Không bắt buộc thoát, chỉ log warning
        log_message("Could not open blacklist file %s", filename);
        return;
    }

    char line[256];
    int count = 0;

    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        // Ví dụ line: "8.8.8.8:53"
        // Tách IP và port
        char *sep = strchr(line, ':');
        if (!sep) {
            continue; // Sai định dạng, bỏ qua
        }

        *sep = '\0';
        char *ip_str = line;
        char *port_str = sep + 1;

        // Chuyển IP => in_addr_t
        struct in_addr addr;
        if (inet_pton(AF_INET, ip_str, &addr) == 1) {
            // parse port
            unsigned short p = (unsigned short)atoi(port_str);
            blacklist_items[count].ip = addr.s_addr; // đã network order
            blacklist_items[count].port = htons(p);  // để nhất quán network order
            count++;
            if (count >= MAX_BLACKLIST) break;
        }
    }

    fclose(fp);

    blacklist_count = count;
    log_message("Loaded %d blacklist entries from %s", blacklist_count, filename);
}

bool is_blacklisted(in_addr_t ip, unsigned short port) {
    for (int i = 0; i < blacklist_count; i++) {
        if ( (blacklist_items[i].ip == ip) && (blacklist_items[i].port == port) ) {
            return true;
        }
    }
    return false;
}