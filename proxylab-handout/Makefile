#Sample Makefile. You can make changes to this file according to your need
# The executable must be named proxy

CC = gcc
CFLAGS = -Wall -g 
LDFLAGS = -pthread	#CHANGE: -lpthread flag changed to -pthread

THREAD_OBJS = thread_proxy.o csapp.o
PROCESS_OBJS = process_proxy.o csapp.o
OBJS = thread_proxy.o process_proxy.o csapp.o

all: process_proxy thread_proxy

process_proxy: $(PROCESS_OBJS)

thread_proxy: $(THREAD_OBJS)

#proxy: $(OBJS)

csapp.o: csapp.c
	$(CC) $(CFLAGS) -c csapp.c

process_proxy.o: process_proxy.c
	$(CC) $(CFLAGS) -c process_proxy.c

thread_proxy.o: thread_proxy.c
	$(CC) $(CFLAGS) -c thread_proxy.c

#proxy.o: proxy.c
#	$(CC) $(CFLAGS) -c proxy.c

clean: process_clean thread_clean

process_clean:
	rm -f *~ csapp.o process_proxy.o process_proxy 

thread_clean:
	rm -f *~ csapp.o thread_proxy.o thread_proxy
