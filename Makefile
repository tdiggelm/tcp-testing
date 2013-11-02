CC      = g++
CFLAGS  = -g -ansi -Wall
LDFLAGS = 

ev-server:	ev-server.cc
			$(CC) $(CFLAGS) ev-server.cc -o ev-server -lev

uv-server:	uv-server.cc
			$(CC) $(CFLAGS) uv-server.cc -o uv-server -luv

clean:
			rm -f *.o *~ ev-server uv-server