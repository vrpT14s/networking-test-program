#include <sys/socket.h>
#include <netinet/in.h>

#include <stdlib.h>
#include <stdio.h>


#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
//#include <nettle/aes.h>
//#include <nettle/twofish.h>
//#include <nettle/cbc.h>
#include <sys/random.h>

#define SA struct sockaddr

void err_sys(const char *message)
{
        perror(message);
        exit(1);
}


void check(int return_val, const char *msg)
{
	if (return_val < 0) err_sys(msg);
}

//returns sockfd or (negative) error;
int connect_to_server(const char *addr_string, const char *port_no)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = 0; //none set

	struct addrinfo *result;
	int return_val = getaddrinfo(addr_string, port_no, &hints, &result);
	if (return_val != 0) {
               fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(return_val));
               exit(EXIT_FAILURE);
	}

	int socket_fd = -1;
	for (struct addrinfo *link = result; link != NULL; link = link->ai_next) {
		socket_fd = socket(link->ai_family,
		                       link->ai_socktype,
				       link->ai_protocol);
		if (socket_fd <= 0) continue;

		printf("trying connection...\n");
		if (connect(socket_fd, link->ai_addr, link->ai_addrlen) >= 0) {
			printf("Connection success\n");
			freeaddrinfo(result);
			return socket_fd;
		}
		printf("connection failed\n");

		close(socket_fd);
		continue;
	}
	printf("no connections successful\n");
	return -1;
}

//returns sockfd representing us or (negative) error;
int wait_for_connection(int port_no, int backlog)
{
	int our_sockfd;
	//socket
	check(our_sockfd = socket(AF_INET6, SOCK_STREAM, 0), "socket");

	//sockopt
	check(setsockopt(our_sockfd,
			IPPROTO_IPV6,
			IPV6_V6ONLY,
			0,
			sizeof(int)),
		"setsockopt");

	struct sockaddr_in6 servaddr;
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin6_family = AF_INET6;
	servaddr.sin6_port = htons(port_no);
	servaddr.sin6_addr = in6addr_any;

	//bind
	check(bind(our_sockfd, (SA*) &servaddr, sizeof(servaddr)), "bind");

	//listen
	check(listen(our_sockfd, backlog), "listen");

	//accept
	int connfd;
	check(connfd = accept(our_sockfd, NULL, NULL), "accept");
	printf("Connected!\n");
	//return our_sockfd;
	return connfd;
}

void dump_buffer(char* buffer_name, char* buffer, size_t buffer_length)
{
	printf("---BUFFER %s, %d BYTES---\n", buffer_name, buffer_length);
	for (int i = 0; i < buffer_length; i++){
		if (i % 8 == 0) printf("\n");
		printf("%02hhx ", (char)buffer[i]);
	}
	printf("\n");
	printf("\n");
}

int main(int argc, char** argv)
{
	//if (argc < 2){
	//	fprintf(stderr, "usage: ./main <message>\n");
	//	exit(1);
	//}
//	struct aes256_ctx ctx;
//	char key[AES256_KEY_SIZE] = {0};
//	((long*)key)[0] = (long)0xdeadfeedbad; //assuming key larger than a long
//	aes256_set_encrypt_key(&ctx, key);
//	//aes256_invert_key(&ctx, &ctx); //sets decrypt key to encryption key
//
//	char message[AES_BLOCK_SIZE*2];
//	memset(message, 0x99, AES_BLOCK_SIZE*2);
//	((long*)message)[0] = (long)0xdeadfeedbad;
//	dump_buffer("message", message, AES_BLOCK_SIZE*2);
//	send_secure_message(message, AES_BLOCK_SIZE*2, &ctx);
//
	int our_sockfd;
	if ( (our_sockfd = connect_to_server("10.60.5.186", "9999")) > 0){
		printf("\nMade connection (as connector).\n");
		char message[] = "hello from connector.\n";
		write(our_sockfd, message, sizeof(message));
		read(our_sockfd, message, sizeof(message));
		printf("%s", message);
	} else if ( (our_sockfd = wait_for_connection(9999, 10)) > 0){
		printf("\nMade connection (as listener).\n");
		char message[] = "hello from listener. (I was started first I think)\n";
		write(our_sockfd, message, sizeof(message));
		read(our_sockfd, message, sizeof(message));
		printf("%s", message);
	}
	close(our_sockfd);
	printf("\nok\n");
	return 0;
}

