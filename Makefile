CC      = g++
CFLAGS  = -g -ansi -Wall
LDFLAGS = 

all:		ev-server uv-server

ev-server:	ev-server.cc
			$(CC) $(CFLAGS) ev-server.cc -o ev-server -lev

uv-server:	uv-server.cc yyincremental/yyparser.cc yyincremental/yylexer.cc
			$(CC) $(CFLAGS) uv-server.cc yyincremental/yyparser.cc yyincremental/yylexer.cc -o uv-server -luv

yyincremental/yyparser.cc:
			make -C yyincremental yyparser.cc

yyincremental/yylexer.cc:
			make -C yyincremental yylexer.cc

.PHONY: clean
clean:
			make -C yyincremental clean
			rm -f *.o *~ ev-server uv-server