#!/bin/bash

# Versions
MAJOR := 0
MINOR := 9
PATCH := 0
VERSION := $(MAJOR).$(MINOR).$(PATCH)
# Utilitys
RM := rm -f
CP := cp
MKDIR := mkdir -p
# Directories
DESTDIR ?=
PREFIX ?= /usr
INSTALL_LOCATION=$(DESTDIR)$(PREFIX)
# Compiler
CC ?= gcc
CFLAGS = -I"include" -DSNT_STR_VERSION=\"$(VERSION)\" -DSNT_MAJOR=$(MAJOR) -DSNT_MINOR=$(MINOR)
CLIBS = -lssl -lcrypto -lz -llz4 -lpthread
# Sources
VPATH = ./src
SRC = $(wildcard src/*.c)
OBJS = $(notdir $(subst .c,.o,$(SRC)))
TARGET ?= snt

all : $(TARGET)
	@echo -n "Finished making $(TARGET). \n"

$(TARGET) : CFLAGS += -O2
$(TARGET) : $(OBJS)
	$(CC) $(CLFAGS) $^ -o $@ $(CLIBS)

debug : CFLAGS += -g3 -O0
debug : $(OBJS)
	$(CC) $(CLFAGS) $^ -o $@ $(CLIBS)

%.o : %.c
	$(CC) $(CFLAGS) -c $^ -o $@

install : $(TARGET)
	@echo -n "Installing snt.\n"
	$(MKDIR) $(INSTALL_LOCATION)/bin
	$(CP) $(TARGET) $(INSTALL_LOCATION)/bin

distribution:
	$(RM) -r $(TARGET)-$(VERSION)
	$(MKDIR) $(TARGET)-$(VERSION)
	$(CP) -r src include Makefile README.md LICENSE *.1 $(TARGET)-$(VERSION)
	tar cf - $(TARGET)-$(VERSION) | gzip -c > $(TARGET)-$(VERSION).tar.gz
	$(RM) -r $(TARGET)-$(VERSION)

clean :
	$(RM) *.o


.PHONY: all install distribution clean debug
