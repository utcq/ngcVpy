
CC      := gcc
CCFLAGS := -c -fPIC -fno-stack-protector -z execstack -no-pie
LCFLAGS := -shared -Wl,-soname,
SOURCES := cngcr/ngcrunner.c
OBJ     := ngc_runner.o
OUTPUT  := ngc_runner.so

all: build

build:
	$(CC) $(SOURCES) $(CCFLAGS) -o $(OBJ)
	$(CC) $(LCFLAGS)$(OUTPUT) -o $(OUTPUT) $(OBJ)
	rm $(OBJ)