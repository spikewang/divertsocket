# @2008 Netsweeper Inc. All Rights Reserved.
# 
# Netsweeper Client Filter - Daemon Makefile
#

CC=g++
CFLAGS=-Wall -g -arch x86_64 -DFIREWALL -DREINJECT 
LDFLAGS=-framework Cocoa -framework SystemConfiguration

OBJS = divert.o 

all: 
	$(CC) $(CFLAGS) -c divert.m -o $(OBJS) 
	$(CC) -o divert $(OBJS) $(LDFLAGS) 

run:
	sudo ./divert 7866

clean: 
	rm -rf *.o *.ko *.a *.dSYM divert 
