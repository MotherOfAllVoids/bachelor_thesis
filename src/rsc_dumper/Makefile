CC          :=  /usr/bin/g++
CFLAGS      :=  -pedantic -Wall -Wextra -std=c++11 -O2
OBJECTS     :=  volume_dumper.o rsc_dumper.o decryptor.o sha2_hasher.o 
LDFLAGS     :=  -lbotan-2
INCS        :=  -I/usr/local/include/botan-2
TARGET	    :=  rsc_dumper 

.PHONY: all clean

all: $(TARGET)

$(TARGET) : $(OBJECTS)
	$(CC) -o $@ $(CFLAGS) $(OBJECTS) $(LDFLAGS)

%.o : %.cpp
	$(CC) $(CFLAGS) $(INCS) -c $< 

clean:
	rm -f $(TARGET) $(OBJECTS)
