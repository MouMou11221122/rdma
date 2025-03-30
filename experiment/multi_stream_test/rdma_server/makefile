CC      = gcc
CFLAGS  = -Wall -g
LIBS    = -libverbs

SRC_DIR = src
OBJ_DIR = obj

SRCS    = $(SRC_DIR)/server.c
OBJS    = $(OBJ_DIR)/server.o
TARGET  = server

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	@$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@rm -rf $(OBJS) $(TARGET)

