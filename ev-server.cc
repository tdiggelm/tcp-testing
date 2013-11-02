/* Copyright (c) 2013 Thomas Diggelmann. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <strings.h>
#include <errno.h>
#include <ev.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define PORT_NO 2001
#define BUFFER_SIZE 1024

int total_clients = 0;  // Total number of connected clients

void make_nonblocking(int fd)
{
    fcntl(fd, F_SETFL, O_NONBLOCK);
}

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

int main()
{	
	struct ev_loop *loop = ev_default_loop(0);
	int sd;
	struct sockaddr_in addr;
	struct ev_io w_accept;

	// ignore sigpipe
	signal(SIGPIPE, SIG_IGN);

	// Create server socket
	if( (sd = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
	{
  		perror("socket error");
  		return -1;
	}

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT_NO);
	addr.sin_addr.s_addr = INADDR_ANY;

	int one = 1;
	if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int)))
	{
	    perror("setsockopt");
	}

	// Bind socket to address
	if (bind(sd, (struct sockaddr*) &addr, sizeof(addr)) != 0)
	{
  		perror("bind error");
	}

	// Start listing on the socket
	if (listen(sd, 0) < 0)
	{
  		perror("listen error");
  		return -1;
	}

	// Initialize and start a watcher to accepts client requests
	ev_io_init(&w_accept, accept_cb, sd, EV_READ);
	ev_io_start(loop, &w_accept);

	// Start infinite loop
	while (1)
	{
  		ev_loop(loop, 0);
	}

	return 0;
}

struct w_io_t {
	ev_io watcher;
};

/* Accept client requests */
void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	int client_sd;
	struct w_io_t *w_client = (struct w_io_t*) malloc (sizeof(struct w_io_t));

	if(EV_ERROR & revents)
	{
  		perror("got invalid event");
  		return;
	}

	// Accept client request
	client_sd = accept(watcher->fd, (struct sockaddr *)&client_addr, &client_len);
	
	// make client nonblocking
	make_nonblocking(watcher->fd);

	if (client_sd < 0)
	{
  		perror("accept error");
  		return;
	}

	total_clients ++; // Increment total_clients count
	printf("Successfully connected with client.\n");
	printf("%d client(s) connected.\n", total_clients);

	// Initialize and start watcher to read client requests
	ev_io_init(&w_client->watcher, read_cb, client_sd, EV_READ);
	ev_io_start(loop, &w_client->watcher);
}

/* Read client message */
void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	char buffer[BUFFER_SIZE];
	ssize_t read;

	if(EV_ERROR & revents)
	{
  		perror("got invalid event");
  		return;
	}

	// Receive message from client socket
	read = recv(watcher->fd, buffer, BUFFER_SIZE, 0);

	if(read < 0)
	{
		if(read == -1 && errno == EAGAIN) {
			printf("got EAGAIN!!!\n");
			exit(1);
			return;
		}
		
  		perror("read error");
  		return;
	}

	if(read == 0)
	{
  		// Stop and free watcher if client socket is closing
  		ev_io_stop(loop,watcher);
		close(watcher->fd);
  		free(watcher);
  		perror("peer might closing");
  		total_clients --; // Decrement total_clients count
  		printf("%d client(s) connected.\n", total_clients);
  		return;
	}
	else
	{
  		//printf("message = %ld bytes\n", read);
	}
	
	char buf[1024];
	sprintf(buf, "message = %ld bytes\n", read);

	// Send message back to the client
	send(watcher->fd, buf, strlen(buf), 0);
	bzero(buffer, read);
}
