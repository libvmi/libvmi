DIRS := $(shell find . -mindepth 1 -maxdepth 1 -type d)

all:
	+make -C build

%:
	+make -C build $@

$(DIRS):
	+make -C build $@


.PHONY: $(DIRS)
