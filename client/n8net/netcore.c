#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_BIND 0x02
#define SOCKS5_CMD_UDP 0x03
#define SOCKS5_VERSION 0x05
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_AUTH_USERPASS 0x02


int send_and_receive(int sockfd, char *send_buffer, size_t send_len, char *recv_buffer, size_t recv_len) {
    // return INT
}

int handshake(int sockfd, char *username, char *password) {
    // Send handshake request to server
}

int make_request(int sockfd, int command, const char *dest_ip, int dest_port) {

}