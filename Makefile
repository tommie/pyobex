SRC = obexmodule.c
CFLAGS = -Wall -O2
CFLAGS += $(shell pkg-config --cflags openobex)
LDFLAGS = $(shell pkg-config --libs openobex)
CFLAGS += $(shell python2-config --cflags) #-I /usr/include/python2.7
LDFLAGS += $(shell python2-config --ldflags)

ifneq ($(HAVE_BLUEZ),)
CFLAGS += $(shell pkg-config --cflags bluez)
LDFLAGS += $(shell pkg-config --libs bluez)
endif

_obex.so: $(SRC)
	$(CC) -shared -fPIC -o $@ $^ $(CFLAGS)  $(LDFLAGS)
