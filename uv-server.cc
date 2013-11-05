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

// TODO: daemonizing server => http://www.itp.uzh.ch/~dpotter/howto/daemonize
// TODO: ?? closing connection: uv_shutdown then close connection in cb to allow buffers
//		 to be written out to client before closing connection
// TODO: investigate possible mem-leak when stressing server with random data

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <uv.h>
#include <getopt.h>
#include "yyincremental/parser.h"

#define UVERR(err, msg) fprintf(stderr, "%s: %s\n", msg, uv_strerror(err))

class intparser;

typedef struct {
	uv_tcp_t handle;
	intparser* parser;
} client_rec;

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req;

static void after_write(uv_write_t* req, int status);
static void after_read(uv_stream_t*, ssize_t nread, const uv_buf_t* buf);
static void on_close(uv_handle_t* peer);
static void on_connection(uv_stream_t*, int status);

class intparser : public parser
{
public:
	intparser(client_rec* client)
		: client(client)
	{}
	
	void write(const char* str)
	{
		write(str, strlen(str));
	}
	
	void write(const char* str, size_t len)
	{
		int ret;
		write_req *wr = (write_req*)malloc(sizeof(write_req));
		wr->buf = uv_buf_init((char*)malloc(len), len);
		memcpy(wr->buf.base, str, len);
		if ((ret = uv_write(&wr->req, (uv_stream_t*)&client->handle, &wr->buf, 1, after_write))) {
			UVERR(ret, "uv_write failed");
			free(wr->buf.base);
			free(wr);
	    }
	}
	
	void quit()
	{
		fprintf(stderr, "client is quitting...\n");
		
		// close if not already closing
		if (!uv_is_closing((uv_handle_t*)&client->handle)) {
			uv_close((uv_handle_t*)&client->handle, on_close);
		}
	}
	
	void foundint(long int num)
	{
		char str[512];
		sprintf(str, "@@@ found int: %ld\n", num);
		write(str);
	}
	
	void error(const char* msg)
	{
		char str[512];
		sprintf(str, "-ERR %s\n", msg);
		write(str);
	}
	
private:
	client_rec* client;
};

static void after_write(uv_write_t* req, int status) {
	write_req* wr = (write_req*)req;
	
  	free(wr->buf.base);
	free(wr);
	
	if (status) UVERR(status, "after_write");
}

static void on_close(uv_handle_t* handle) {
    client_rec* client = (client_rec*)handle;
	delete client->parser;
    free(client);
}

void hexdump(void *ptr, int buflen) {
  unsigned char *buf = (unsigned char*)ptr;
  int i, j;
  for (i=0; i<buflen; i+=16) {
    printf("%06x: ", i);
    for (j=0; j<16; j++) 
      if (i+j < buflen)
        printf("%02x ", buf[i+j]);
      else
        printf("   ");
    printf(" ");
    for (j=0; j<16; j++) 
      if (i+j < buflen)
        printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
    printf("\n");
  }
}

static void after_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
	client_rec* client = (client_rec*)stream;

	if (nread < 0) {
		if (buf->base) {
			free(buf->base);
		}
		
		if (nread == UV_EOF) {
			printf("client disconnects\n");
		} else {
			UVERR(nread, "after_read");	
		}
		
		uv_close((uv_handle_t*)&client->handle, on_close);
		return;
	}
	
	client->parser->feed(buf->base, nread);
	client->parser->parse();

	if (buf->base) {
		free(buf->base);
	}
}

static void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
	buf->base = (char*)malloc(suggested_size);
	buf->len = suggested_size;
}

static void on_connection(uv_stream_t* server, int status) {
	int ret;
	
	uv_loop_t* loop = uv_default_loop();
	
	if (status != 0) {
		fprintf(stderr, "Connect error %s\n", uv_err_name(status));
	}
	assert(status == 0);

	client_rec* client = (client_rec*)malloc(sizeof (client_rec));
	assert(client != NULL);

    ret = uv_tcp_init(loop, &client->handle);
    assert(ret == 0);

	ret = uv_accept(server, (uv_stream_t*)&client->handle);
	assert(ret == 0);
	
	client->parser = new intparser(client);
	assert(client->parser != NULL);
	
	ret = uv_read_start((uv_stream_t*)&client->handle, on_alloc, after_read);
	assert(ret == 0);
}

void usage() {
	printf(
		"usage: uv-server [OPTION ...]\n"
		"   --help, -h			display this help message\n"
		"   --socket, -s SOCK_FILE	listening on socket SOCK_FILE\n"
		"   --port, -p PORT		listening on PORT (0 disables tcp socket)\n"
	);
}

int main(int argc, char **argv) {
	int port = 3000;
	char* socket = NULL;

	int c;
	while (1)
	{
		static struct option long_options[] = {
			{"help",	no_argument,		0,	'h'},
			{"socket",	required_argument,	0,	's'},
			{"port",	required_argument,	0,	'p'},
			{0, 0, 0, 0}
		};
		
		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long (argc, argv, "s:p:h", long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1) break;

		switch (c)
		{
			case 's': socket = optarg; break;
			case 'p': port = atoi(optarg); break;
			case 'h':
			default: usage(); exit(1);
		}
	}
	
	if (socket == NULL && port == 0) {
		fprintf(stderr, "fatal: server has no endpoint.\n");
		exit(1);
	}

	uv_loop_t* loop = uv_default_loop();
	uv_tcp_t tcpServer;
	uv_pipe_t pipe;

	// ignore sigpipe (client exits before write completes) to prevenet
	// server from exiting
	signal(SIGPIPE, SIG_IGN);
	
	int ret;

	if (port)
	{
		struct sockaddr_in addr;
		assert(0 == uv_ip4_addr("0.0.0.0", 3000, &addr));

		if ((ret = uv_tcp_init(loop, &tcpServer))) {
			/* TODO: Error codes */
			UVERR(ret, "Socket creation error");
			return 1;
		}

		if ((ret = uv_tcp_bind(&tcpServer, (const struct sockaddr*) &addr))) {
			/* TODO: Error codes */
			UVERR(ret, "Bind error");
			return 1;
		}

		if ((ret = uv_listen((uv_stream_t*)&tcpServer, SOMAXCONN, on_connection))) {
			/* TODO: Error codes */
			UVERR(ret, "Listen error");
			return 1;
		}
		
		printf("listening on port %d...\n", port);
	}
	
	if (socket)
	{
		// remove socket file if already existing
		// don't care if it failes
		remove(socket);
		
		if ((ret = uv_pipe_init(loop, &pipe, 0))) {
			/* TODO: Error codes */
			UVERR(ret, "Pipe creation error");
			return 1;
		}
		
		if ((ret = uv_pipe_bind(&pipe, socket))) {
	        UVERR(ret, "Pipe bind error");
	        return 1;
	    }
	
		if ((ret = uv_listen((uv_stream_t*)&pipe, SOMAXCONN, on_connection))) {
			/* TODO: Error codes */
			UVERR(ret, "Listen error");
			return 1;
		}
		
		printf("listening on socket '%s'...\n", socket);
	}

	uv_run(loop, UV_RUN_DEFAULT);

	return 0;
}
