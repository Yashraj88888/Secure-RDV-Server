CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g -pthread -Iinclude -I/opt/homebrew/opt/openssl@3/include
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -lpthread

SRCS = src/main.c src/server_core.c src/client_handler.c \
       src/screen_capture.c src/db_logger.c src/crypto_utils.c

TARGET = rdv_server

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "Build successful: ./$(TARGET)"

clean:
	rm -f $(TARGET) rdv_sessions.log

distclean: clean
	rm -f server.crt server.key

.PHONY: all clean distclean
