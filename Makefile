PROG=test uprobe py
CC=clang
ARCH=x86
CFLAGS=-g -O2
BPFTOOL=bpftool
SKEL=$(patsubst %,%.skel.h,$(PROG))
BPF_TMP_OBJS=$(patsubst %,%.tmp.bpf.o,$(PROG))
BPF_TMP_DEPS=$(patsubst %.o,%.d,$(BPF_TMP_OBJS))
BPF_OBJS=$(patsubst %,%.bpf.o,$(PROG))
OBJS=$(patsubst %,%.o,$(PROG))
DEPS=$(patsubst %.o,%.d,$(OBJS))

.PHONY: all
all: $(PROG)
	@:

$(BPF_TMP_OBJS): %.tmp.bpf.o: %.bpf.c
	$(CC) -c $< -o $@ -target bpf $(CFLAGS) -D__TARGET_ARCH_$(ARCH)

$(BPF_OBJS): %.bpf.o: %.tmp.bpf.o
	$(BPFTOOL) gen object $@ $<

$(SKEL): %.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(OBJS): %.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

$(PROG): %: %.o
	$(CC) -o $@ $< $(CFLAGS) -lbpf -lelf -lz

$(DEPS): %.d: %.c %.skel.h
	$(CC) -MM -MP -MT $(@:.d=.o) $< -o $@

$(BPF_TMP_DEPS): %.tmp.bpf.d: %.bpf.c
	$(CC) -MM -MP -MT $(@:.d=.o) $< -o $@

include $(DEPS)
include $(BPF_TMP_DEPS)

.PHONY: clean
clean:
	-$(RM) $(PROG) $(OBJS) $(BPF_TMP_OBJS) $(BPF_OBJS) $(SKEL) $(DEPS) $(BPF_TMP_DEPS)
