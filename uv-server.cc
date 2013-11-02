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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <uv.h>
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

static uv_loop_t* _loop;
static uv_tcp_t _tcpServer;

static void after_write(uv_write_t* req, int status);
static void after_read(uv_stream_t*, ssize_t nread, const uv_buf_t* buf);
static void on_close(uv_handle_t* peer);
static void on_connection(uv_stream_t*, int status);

class intparser : public parser
{
public:
	intparser(uv_stream_t* stream)
		: stream(stream)
	{}
	
	void write(const char* str)
	{
		write(str, strlen(str));
	}
	
	void write(const char* str, size_t len)
	{
		write_req *wr = (write_req*)malloc(sizeof(write_req));
		wr->buf = uv_buf_init((char*)malloc(len), len);
		memcpy(wr->buf.base, str, len);
		if (uv_write(&wr->req, stream, &wr->buf, 1, after_write)) {
			fprintf(stderr, "uv_write failed\n");
	  		assert(!"uv_write failed");
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
	uv_stream_t* stream;
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
		
		//assert(nread == UV_EOF);
		
		if (nread == UV_EOF) {
			printf("client disconnects\n");
		} else {
			UVERR(nread, "after_read");	
		}
		
		uv_close((uv_handle_t*)&client->handle, on_close);
		return;
	}
	
	if (strncmp(buf->base, "exit", 4) == 0) {
		if (buf->base) {
			free(buf->base);
		}
		printf("received 'exit'\n");
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
	int r;
	
	if (status != 0) {
		fprintf(stderr, "Connect error %s\n", uv_err_name(status));
	}
	assert(status == 0);

	client_rec* client = (client_rec*)malloc(sizeof (client_rec));
	assert(client != NULL);

    r = uv_tcp_init(_loop, &client->handle);
    assert(r == 0);

	r = uv_accept(server, (uv_stream_t*)&client->handle);
	assert(r == 0);
	
	client->parser = new intparser((uv_stream_t*)&client->handle);
	assert(client->parser != NULL);
	
	r = uv_read_start((uv_stream_t*)&client->handle, on_alloc, after_read);
	assert(r == 0);
}

int main() {
	printf("listening on port 3000...\n");
                         
	// ignore sigpipe (client exits before write completes) to prevenet
	// server from exiting
	signal(SIGPIPE, SIG_IGN);
	                   
	_loop = uv_default_loop();

	struct sockaddr_in addr;
	int r;

	assert(0 == uv_ip4_addr("0.0.0.0", 3000, &addr));

	r = uv_tcp_init(_loop, &_tcpServer);
	if (r) {
		/* TODO: Error codes */
		fprintf(stderr, "Socket creation error\n");
		return 1;
	}

	r = uv_tcp_bind(&_tcpServer, (const struct sockaddr*) &addr);
	if (r) {
		/* TODO: Error codes */
		fprintf(stderr, "Bind error\n");
		return 1;
	}

	r = uv_listen((uv_stream_t*)&_tcpServer, SOMAXCONN, on_connection);
	if (r) {
		/* TODO: Error codes */
		fprintf(stderr, "Listen error %s\n", uv_err_name(r));
		return 1;
	}

	uv_run(_loop, UV_RUN_DEFAULT);

	return 0;
}
