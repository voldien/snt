#!/bin/bash

# Versions
MAJOR := 0
MINOR := 13
PATCH := 0
STATE := b
VERSION := $(MAJOR).$(MINOR)$(STATE)$(PATCH)
# Utilities
RM := rm -f
CP := cp
MKDIR := mkdir -p
CHMOD := chmod
CHOWN := chown
# Crypto utility
OPENSSL := openssl
# Directories
DESTDIR ?=
PREFIX ?= /usr
INSTALL_LOCATION=$(DESTDIR)$(PREFIX)
SSL_DIR := $(DESTDIR)/etc/ssl
# Compiler
CC ?= cc
CFLAGS = -I"include" -DSNT_STR_VERSION=\"$(VERSION)\" -DSNT_MAJOR=$(MAJOR) -DSNT_MINOR=$(MINOR)
CLIBS = -lssl -lcrypto -lz -llz4 -lpthread -lbz2
# Sources
VPATH = ./src
SRC = $(wildcard src/*.c)
OBJS = $(notdir $(subst .c,.o,$(SRC)))
SERVICE := sntd
SERVICED := sntd.service
# Main Targets
TARGET ?= snt
# Certificates files
DHPEM := sntdh.pem
DHPARAM ?= 2048
RSAPRIV := snt.pem
RSACERT := snt.cert
RSAPARAM ?= 2048

all : $(TARGET)
	@echo -n "Finished making $(TARGET). \n"

$(TARGET) : CFLAGS += -O2 -DNDEBUG
$(TARGET) : $(OBJS)
	$(CC) $(CLFAGS) $^ -o $@ $(CLIBS)

debug : CFLAGS += -g3 -O0
debug : $(OBJS)
	$(CC) $(CLFAGS) $^ -o $(TARGET) $(CLIBS)

%.o : %.c
	$(CC) -MMD $(CFLAGS) -c $< -o $@

install : $(TARGET)
	@echo -n "Installing snt.\n"
	$(MKDIR) $(INSTALL_LOCATION)/bin
	$(CP) $(TARGET) $(INSTALL_LOCATION)/bin
	$(CP) snt.bc $(INSTALL_LOCATION)/share/bash-completion/completions/snt
	$(MKDIR) $(INSTALL_LOCATION)/share/man/man1/
	gzip -ck snt.1  > snt.1.gz
	$(CP) snt.1.gz $(INSTALL_LOCATION)/share/man/man1/

install_wireshark_dissector:
	@echo -n "Installing wireshark dissector.\n"
	$(MKDIR) $(HOME)/.wireshark/plugins
	$(CP) snt.lua $(HOME)/.wireshark/plugins/snt.lua

install_service:
	$(CP) $(SERVICE) /etc/init.d
	$(CP) $(SERVICED) /etc/systemd/system
	@echo -n "Installed service daemon.\n"

$(DHPEM) :
	@echo -n "Generating Diffie hellman $(DHPARAM) bit key.\n"
	$(OPENSSL) dhparam $(DHPARAM) -out $@

$(RSAPRIV) :
	@echo -n "Generate RSA $(RSAPARAM) private key.\n"
	$(OPENSSL) genrsa -out $@ -F4 $(RSAPARAM)

$(RSACERT) : $(RSAPRIV)
	@echo -n "Generating RSA $(RSAPARAM) certificate file.\n"
	$(OPENSSL) req -nodes -new -x509 -key $^ -out $@


cert: $(DHPEM) $(RSAPRIV) $(RSACERT)
	@echo -n "Generated certificates and keys.\n"

install_cert: cert
	@echo -n "Install diffie hellman pem file.\n"
	$(CP) $(DHPEM) $(SSL_DIR)/certs
	$(CHMOD) 644 $(SSL_DIR)/certs/$(DHPEM)
	$(CHOWN) root:ssl-cert $(SSL_DIR)/certs/$(DHPEM)
	@echo -n "Install RSA private key pem file.\n"
	$(MKDIR) ~/.snt
	$(CP) $(RSAPRIV) ~/.snt
	$(CHMOD) 400 ~/.snt/$(RSAPRIV)
	@echo -n "Install RSA X509 certificate file.\n"
	$(CP) $(RSACERT) $(SSL_DIR)/certs
	$(CHMOD) 644 $(SSL_DIR)/certs/$(RSACERT)
	$(CHOWN) root:ssl-cert $(SSL_DIR)/certs/$(RSACERT)

distribution:
	$(RM) -r $(TARGET)-$(VERSION)
	$(MKDIR) $(TARGET)-$(VERSION)
	$(CP) -r src include Makefile README.md LICENSE *.1 snt.bc snt.lua sntd $(TARGET)-$(VERSION)
	tar cf - $(TARGET)-$(VERSION) | gzip -c > $(TARGET)-$(VERSION).tar.gz
	$(RM) -r $(TARGET)-$(VERSION)

clean :
	$(RM) *.o *.d

-include *.d

.PHONY: all install distribution clean debug install_wireshark_dissector install_service install_cert cert

