TARGET = test

PV_SUPPORT = y

ifeq ($(PV_SUPPORT),y)
CFLAGS = -DPATH_VECTOR_INCLUDED
endif

#INC_PATH += -I.
INC_PATH = -I../include/quagga

LIBS += -lpthread
LIBS += -lrt

####### Implicit rules
.c.o:
	gcc -c  $(CFLAGS) $(INC_PATH) $< -o $@

#PROTOIPC_OBJS = ../lib/libzebra.a
PROTOIPC_OBJS = ../lib/libzebra.so

####### Files
HEADERS = $(wildcard ./*.h)
SOURCES = $(wildcard ./*.c)
OBJECTS = $(patsubst %.c, %.o, $(SOURCES))

all: ${OBJECTS} ${TARGET}

		@echo "###################################"
		@echo "#             ${TARGET}      "
		@echo "#        Build up successfully"
		@echo "###################################"

$(TARGET): 
	gcc -o $@ $(CFLAGS) ${OBJECTS} ${PROTOIPC_OBJS} ${LIBS}  

clean:
	rm -rf ${OBJECTS} ${TARGET}

