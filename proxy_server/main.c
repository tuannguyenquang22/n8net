#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <pthread.h>

#define SOCKS5_VERSION 0x05
#define METHOD_USERNAME_PASSWORD 0x02
#define METHOD_NO_ACCEPTABLE 0xFF
#define CMD_CONNECT 0x01
#define CMD_BIND 0x02
#define CMD_UDP_ASSOCIATE 0x03
#define ATYP_IPV4 0x01
#define ATYP_DOMAINNAME 0x03
#define BUFFER_SIZE 4096

typedef struct {
    int client_sock;
} client_data_t;

void *handle_client(void *arg);
int authenticate(int client_sock);
int validate_user(const char *username, const char *password);
void print_hex(const unsigned char *buffer, size_t length);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int server_sock;
    struct sockaddr_in server_addr;
    int port = atoi(argv[1]);

    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    if (listen(server_sock, 5) < 0) {
        perror("Listen failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    printf("SOCKS5 Proxy Server running on port %d\n", port);

    while(1) {
        int client_sock;
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);

        // Accept client connection
        if ((client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_addr_len)) < 0) {
            perror("Accept failed");
            continue;
        }

        printf("New connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // Create client data
        client_data_t *client_data = malloc(sizeof(client_data_t));
        client_data->client_sock = client_sock;


        // Create a new thread to handle client
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, client_data) != 0) {
            perror("Thread creation failed");
            close(client_sock);
            free(client_data);
        } 

        // Automatically detach thread after completion
        pthread_detach(thread_id);
    }

    close(server_sock);
    return 0;
}

void *handle_client(void *arg) {
    client_data_t *client_data = (client_data_t *)arg;
    int client_sock = client_data->client_sock;
    free(client_data);

    unsigned char buffer[BUFFER_SIZE];
    ssize_t n;

    // Handshake
    if ((n = recv(client_sock, buffer, BUFFER_SIZE, 0)) <= 0) {
        perror("Receive failed");
        close(client_sock);
        return NULL;
    }

    if (buffer[0] != SOCKS5_VERSION) {
        fprintf(stderr, "Invalid SOCKS version\n");
        close(client_sock);
        return NULL;
    }

    unsigned char response[2] = {SOCKS5_VERSION, METHOD_USERNAME_PASSWORD};
    if (send(client_sock, response, 2, 0) != 2) {
        perror("Send failed");
        close(client_sock);
        return NULL;
    }

    // Authenticate USERNAME/PASSWORD
    if (!authenticate(client_sock)) {
        fprintf(stderr, "Authentication failed\n");
        close(client_sock);
        return NULL;
    }

    if ((n = recv(client_sock, buffer, BUFFER_SIZE, 0)) <= 0) {
        perror("Receive failed");
        close(client_sock);
        return NULL;
    }

    if (buffer[0] != SOCKS5_VERSION) {
        fprintf(stderr, "Unsupported command\n");
        close(client_sock);
        return NULL;
    }

    switch (buffer[1]) {
        case CMD_CONNECT: {
            // Handle CMD_CONNECT
            struct sockaddr_in target_addr;
            target_addr.sin_family = AF_INET;
            memcpy(&target_addr.sin_addr.s_addr, &buffer[4], 4);
            target_addr.sin_port = *(uint16_t *)&buffer[8];

            int remote_sock = socket(AF_INET, SOCK_STREAM, 0);
            if (remote_sock < 0 || connect(remote_sock, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
                perror("Connection to target failed");
                unsigned char reply[] = {SOCKS5_VERSION, 0x05};
                send(client_sock, reply, sizeof(reply), 0);
                close(client_sock);
                return NULL;
            }

            unsigned char reply[] = {SOCKS5_VERSION, 0x00, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0};
            send(client_sock, reply, sizeof(reply), 0);

            while (1) {
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(client_sock, &fds);
                FD_SET(remote_sock, &fds);

                int max_fd = client_sock > remote_sock ? client_sock : remote_sock;
                if (select(max_fd + 1, &fds, NULL, NULL, NULL) < 0) break;

                if (FD_ISSET(client_sock, &fds)) {
                    int n = recv(client_sock, buffer, BUFFER_SIZE, 0);
                    if (n <= 0) break;
                    send(remote_sock, buffer, n, 0);
                }

                if (FD_ISSET(remote_sock, &fds)) {
                    int n = recv(remote_sock, buffer, BUFFER_SIZE, 0);
                    if (n <= 0) break;
                    send(client_sock, buffer, n, 0);
                }
            }

            close(remote_sock);
            break;
        }
        case CMD_BIND: {
            // Handle CMD_BIND
            int bind_sock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in bind_addr;
            bind_addr.sin_family = AF_INET;
            bind_addr.sin_addr.s_addr = INADDR_ANY;
            bind_addr.sin_port = 0;

            if (bind(bind_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
                perror("Bind failed");
                unsigned char reply[] = {SOCKS5_VERSION, 0x05};
                send(client_sock, reply, sizeof(reply), 0);
                close(client_sock);
                return NULL;
            }

            listen(bind_sock, 1);
            
            struct sockaddr_in actual_addr;
            socklen_t addr_len = sizeof(actual_addr);
            getsockname(bind_sock, (struct sockaddr *)&actual_addr, &addr_len);

            unsigned char reply[10] = {SOCKS5_VERSION, 0x00, 0x00, ATYP_IPV4};

            memcpy(&reply[4], &actual_addr.sin_addr.s_addr, 4);
            memcpy(&reply[8], &actual_addr.sin_port, 2);
            send(client_sock, reply, sizeof(reply), 0);

            int remote_sock = accept(bind_sock, NULL, NULL);
            close(bind_sock);

            while (1) {
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(client_sock, &fds);
                FD_SET(remote_sock, &fds);

                int max_fd = client_sock > remote_sock ? client_sock : remote_sock;
                if (select(max_fd + 1, &fds, NULL, NULL, NULL) < 0) break;

                if (FD_ISSET(client_sock, &fds)) {
                    int n = recv(client_sock, buffer, BUFFER_SIZE, 0);
                    if (n <= 0) break;
                    send(remote_sock, buffer, n, 0);
                }

                if (FD_ISSET(remote_sock, &fds)) {
                    int n = recv(remote_sock, buffer, BUFFER_SIZE, 0);
                    if (n <= 0) break;
                    send(client_sock, buffer, n, 0);
                }
            }

            close(remote_sock);
            break;
        }
        case CMD_UDP_ASSOCIATE: {
            // Handle CMD_UDP_ASSOCIATE
            struct sockaddr_in udp_addr;
            udp_addr.sin_family = AF_INET;
            udp_addr.sin_addr.s_addr = INADDR_ANY;
            udp_addr.sin_port = 0;

            int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (bind(udp_sock, (struct sockaddr *)&udp_addr, sizeof(udp_addr)) < 0) {
                perror("UDP Bind failed");
                unsigned char reply[] = {SOCKS5_VERSION, 0x05};
                send(client_sock, reply, sizeof(reply), 0);
                close(client_sock);
                return NULL;
            }

            struct sockaddr_in actual_addr;
            socklen_t addr_len = sizeof(actual_addr);
            getsockname(udp_sock, (struct sockaddr *)&actual_addr, &addr_len);

            unsigned char reply[10] = {SOCKS5_VERSION, 0x00, 0x00, ATYP_IPV4};

            memcpy(&reply[4], &actual_addr.sin_addr.s_addr, sizeof(actual_addr.sin_addr.s_addr));
            memcpy(&reply[8], &actual_addr.sin_port, sizeof(actual_addr.sin_port));
            send(client_sock, reply, sizeof(reply), 0);

            while (1) {
                char udp_buffer[BUFFER_SIZE];
                struct sockaddr_in client_udp_addr;
                socklen_t client_udp_len = sizeof(client_udp_addr);

                int n = recvfrom(udp_sock, udp_buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_udp_addr, &client_udp_len);
                if (n <= 0) break;

                sendto(udp_sock, udp_buffer, n, 0, (struct sockaddr *)&client_udp_addr, client_udp_len);
            }

            close(udp_sock);
            break;
        }
        default:
            fprintf(stderr, "Unsupported command\n");
            break;
    }

    close(client_sock);
    return NULL;
}

int authenticate(int client_sock) {
    unsigned char buffer[BUFFER_SIZE];
    ssize_t n;

    if ((n = recv(client_sock, buffer, BUFFER_SIZE, 0)) <= 0) {
        perror("Receive failed");
        return 0;
    }

    unsigned char username_len = buffer[1];
    char username[256] = {0};
    strncpy(username, (char *)&buffer[2], username_len);

    unsigned char password_len = buffer[2 + username_len];
    char password[256] = {0};
    strncpy(password, (char *)&buffer[3 + username_len], password_len);

    if (validate_user(username, password)) {
        unsigned char response[2] = {0x01, 0x00};
        send(client_sock, response, 2, 0);
        return 1;
    } else {
        unsigned char response[2] = {0x01, 0x01};
        send(client_sock, response, 2, 0);
        return 0;
    }
}

int validate_user(const char *username, const char *password) {
    FILE *file = fopen("nguoidung.txt", "r");
    if (!file) {
        perror("Failed to open user file");
        return 0;
    }

    char line[512];
    while (fgets(line, sizeof(line), file)) {
        char file_username[256], file_password[256];
        if (sscanf(line, "%255[^:]:%255s", file_username, file_password) == 2) {
            if (strcmp(username, file_username) == 0 && strcmp(password, file_password) == 0) {
                fclose(file);
                return 1;
            }
        }
    }

    fclose(file);
    return 0;
}

void print_hex(const unsigned char *buffer, size_t length) {
    printf("Received handshake request (hex): ");
    for (size_t i = 0; i < length; i++) {
        printf("%02x ", buffer[i]); // Print each byte as a 2-digit hexadecimal number
    }
    printf("\n");
}