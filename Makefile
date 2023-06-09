VMM_BIN=vmm

#CC=gcc -std=gnu11 -Wall -Wextra -MMD -fsanitize=address -fsanitize=undefined -g -I../

CC=gcc -std=gnu11 -Wall -Wextra -MMD -g -O3

SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)
DEPS=$(OBJS:%.o=%.d)

$(VMM_BIN): $(OBJS)
	$(CC) $^ -o $@

%.o: %.c
	$(CC) -c $< -o $@

clean:
	rm -f $(OBJS) $(DEPS) $(VMM_BIN)

run: $(VMM_BIN)
	./$<

.PHONY: clean

-include $(DEPS)
