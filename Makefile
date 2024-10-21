.PHONY: clean cleanobj

CC			:= cc
LD			:= $(CC)

ifeq ($(shell which $(CC)),)
$(error C compiler does not exist!) 
endif

TOP_DIR		:= $(PWD)
CFLAGS		:= -D NDEBUG -Wall -Wextra -Wno-invalid-utf8 -Wno-unused -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

ifeq ($(shell $(CC) -E -xc -include unistd.h -o /dev/null /dev/null 2>&1),)
CFLAGS		+= -D HAVE_UNISTD_H
endif

ifneq ($(shell $(CC) -v 2>&1 | grep -i -c "mingw"), 0)
LDFLAGS		:= -static-libgcc
endif

OBJ_DIR	:= $(TOP_DIR)/$(CC)_obj
BIN_DIR	:= $(TOP_DIR)/$(CC)_bin

APP	:= $(BIN_DIR)/zxcfg

vpath %.c src deps/zlib

C_SRCS		:= $(notdir $(wildcard ./src/*.c))
C_SRCS		+= $(notdir $(wildcard ./deps/zlib/*.c))
C_OBJS		:= $(C_SRCS:%.c=$(OBJ_DIR)/%.o)
C_DEPS		:= $(C_OBJS:%.o=%.d)

all: CHECKDIR $(C_OBJS) $(APP)
	@echo done.

CHECKDIR:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

-include $(C_DEPS)
$(C_OBJS):$(OBJ_DIR)/%.o:%.c
	$(CC) -c $(CFLAGS) -Wp,-MMD,"$(@:%.o=%.d)" -MT"$@" -o $@ $<

$(APP): $(C_OBJS)
	@echo "---- Build : $@ ----"
	$(LD) $^ $(LDFLAGS) -o $@

clean:
	rm -f $(OBJ_DIR)/*.o
	rm -f $(OBJ_DIR)/*.d
	rm -f $(APP)

cleanobj:
	rm -f $(OBJ_DIR)/*.o
	rm -f $(OBJ_DIR)/*.d
