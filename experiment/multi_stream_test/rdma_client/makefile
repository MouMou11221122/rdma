CC      = gcc
CFLAGS  = -Wall -g 
LIBS    = -libverbs

SRC_DIR = src
OBJ_DIR = obj

SRCS    = $(SRC_DIR)/client.c
OBJS    = $(OBJ_DIR)/client.o
TARGET  = client

ifdef TEST_MULTI_STREAM
CFLAGS += -DTEST_MULTI_STREAM=$(TEST_MULTI_STREAM)
endif

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	@$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@rm -rf $(OBJS) $(TARGET)

