TARGET		:=  bcve_otfe 
ALL_COMP    :=  bcve_rsc_parser bcve_otfe
CC		    := /usr/bin/g++
CFLAGS		:= -pedantic -Wall -Wextra -std=c++11 -O2
LDFLAGS		:= -L./BUSE-master -lbuse -lbotan-2
INCS        := -I/usr/local/include/botan-2

.PHONY: all clean buse

all: $(TARGET)

buse:
	$(MAKE) -C BUSE-master all

$(TARGET): %: $(ALL_COMP:=.o) buse
	$(CC) -o $@ $(ALL_COMP:=.o) $(LDFLAGS)

$(ALL_COMP:=.o): %.o: %.cpp
	$(CC) $(CFLAGS) $(INCS) -o $@ -c $<

clean:
	$(MAKE) -C BUSE-master clean
	rm -f $(TARGET) $(ALL_COMP:=.o)
