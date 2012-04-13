SRC = obexmodule.c
CFLAGS = -Wall -O2
CFLAGS += -I /usr/include/python2.7
CFLAGS += `pkg-config --cflags openobex bluez`
LDFLAGS = `pkg-config --libs openobex bluez`
_obex.so: $(SRC)
	$(CC) -shared -fPIC -o $@ $^ $(CFLAGS)  $(LDFLAGS)
