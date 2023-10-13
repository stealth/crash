#
#
#


INC=
LIBS=
CXXFLAGS=
DEFS=-DTITLE="\"[kthreadd]\""

# comment in if you want to have server and client support TLS 1.2 in order
# to use aged systems that have no TLS 1.3 libcrypto support, which is otherwise
# the minimum TLS version
#DEFS+=-DTLS_COMPAT_DOWNGRADE

# Do not enable. !For debugging only!
# -DUSE_CCIPHERS="\"NULL@SECLEVEL=0\"" -DUSE_SCIPHERS="\"NULL@SECLEVEL=0\""

# comment out if you want DTLSv1_listen() "DoS protection" for OpenSSL-3 or LibreSSL-3
# do not comment out if you want suspend/resume
DEFS+=-DNO_DTLS_LISTEN

#SSL=/opt/ssl/libressl-3.7.0

ifeq ($(shell uname), Linux)
	LIBS+=-lssl -lcrypto -Wl,--rpath=$(SSL)/lib -Wl,--rpath=$(SSL)/lib64
	DEFS+=-DHAVE_UNIX98
else ifeq ($(shell uname), Solaris)
	LIBS+=-lssl -lcrypto -lsocket -lnsl
else ifeq ($(shell uname), Darwin)
	SSL=/usr/local/opt/openssl\@1.1
	LIBS+=-lssl -lcrypto
	DEFS+=-DHAVE_UNIX98
else
	LIBS+=-lssl -lcrypto -lutil
endif


CXX?=c++
CXXSTD?=c++11
INC+=-I$(SSL)/include
CXXFLAGS+=-Wall -O2 -std=$(CXXSTD) -pedantic $(INC) $(DEFS)

LIBS+=-L$(SSL)/lib -L$(SSL)/lib64
LDFLAGS=-lpthread
LD=$(CXX)
STRIP=strip

CNF=../contrib/openssl.cnf

all: crashd crashc

clean:
	rm -rf *.o

keys:
	umask 066
	@echo "***** Generating Keys ****"
	@echo
	@echo "Whatever you enter for Country/Organization etc is not important (press enter)."
	@echo "Just the passphrase is important"
	@echo
	@echo "**************************"
	sleep 3
	OPENSSL_CONF=$(CNF) openssl genrsa -out serverkey.priv 4096
	OPENSSL_CONF=$(CNF) openssl req -new -x509 -nodes -sha1 -key serverkey.priv -out serverkey.pub
	OPENSSL_CONF=$(CNF) openssl x509 -in serverkey.pub -pubkey -noout > HK_127.0.0.1
	OPENSSL_CONF=$(CNF) openssl genrsa -out authkey.priv -aes256 4096
	OPENSSL_CONF=$(CNF) openssl rsa -in authkey.priv -pubout -out authkey.pub
	@echo
	@echo
	@echo "Your serverkey is in serverkey.{priv,pub} and authentication (user-) key in"
	@echo "authkey.{priv,pub}. Copy authkey.pub to ~/.crash/authorized_keys on remote"
	@echo "server and use '-i authkey.priv' on the client to connect to it"
	@echo
	@echo "Your known-host key which belongs to serverkey.priv is in HK_127.0.0.1"
	@echo "and you can use it with '-K HK_127.0.0.1' on the client (127.0.0.1 as example)"
	@echo
	@echo "For example you can start './crashd' as root on localhost and use"
	@echo "'./crashc -K ./HK_127.0.0.1 -H 127.0.0.1 -l user -i authkey.priv'"
	@echo "to login."
	@echo

crashc: net.o misc.o crashc.o config.o session.o csession.o global.o missing.o
	$(LD) net.o misc.o crashc.o config.o pty.o global.o pty98.o session.o csession.o missing.o $(LIBS) $(LDFLAGS) -o crashc
	$(STRIP) crashc

crashd: server.o session.o ssession.o net.o misc.o crashd.o config.o pty.o pty98.o global.o log.o dh.o iobox.o missing.o
	$(LD) server.o session.o ssession.o net.o misc.o crashd.o config.o pty.o pty98.o global.o log.o dh.o iobox.o missing.o $(LIBS) $(LDFLAGS) -o crashd
	$(STRIP) crashd

missing.o: missing.cc
	$(CXX) $(CXXFLAGS) -c missing.cc

iobox.o: iobox.cc
	$(CXX) $(CXXFLAGS) -c iobox.cc

server.o: server.cc
	$(CXX) $(CXXFLAGS) -c server.cc

session.o: session.cc
	$(CXX) $(CXXFLAGS) -c session.cc

ssession.o: ssession.cc
	$(CXX) $(CXXFLAGS) -c ssession.cc

csession.o: csession.cc
	$(CXX) $(CXXFLAGS) -c csession.cc

net.o: net.cc
	$(CXX) $(CXXFLAGS) -c net.cc

misc.o: misc.cc
	$(CXX) $(CXXFLAGS) -c misc.cc

config.o: config.cc
	$(CXX) $(CXXFLAGS) -c config.cc

pty.o: pty.cc
	$(CXX) $(CXXFLAGS) -c pty.cc

pty98.o: pty98.cc
	$(CXX) $(CXXFLAGS) -c pty98.cc

global.o: global.cc
	$(CXX) $(CXXFLAGS) -c global.cc

log.o: log.cc
	$(CXX) $(CXXFLAGS) -c log.cc

crashd.o: crashd.cc
	$(CXX) $(CXXFLAGS) -c crashd.cc

crashc.o: crashc.cc
	$(CXX) $(CXXFLAGS) -c crashc.cc

dh.o: dh.cc dh2048.cc
	$(CXX) $(CXXFLAGS) -c dh.cc

