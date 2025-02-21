CC      = gcc
CFLAGS  = -Wall -g -DTEST_MULTI_STREAM
LDLIBS  = -libverbs

SRC_DIR = src
OBJ_DIR = obj

SRCS    = $(SRC_DIR)/client.c
OBJS    = $(OBJ_DIR)/client.o
TARGET  = client

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	@$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@rm -rf $(OBJS) $(TARGET)

