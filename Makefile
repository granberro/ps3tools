TOOLS	=	readself pupunpack unself sceverify unself2 norunpkg
TOOLS	+=	makeself norunpack puppack unpkg pkg patchself patchself2
TOOLS	+=	cosunpkg cospkg ungpkg readselfo scekrit nandunpack readmeta
TOOLS	+=	readedata self_rebuilder readself2 gpkg eEID-SPLIT
COMMON	=	tools.o aes.o sha1.o ec.o bn.o self.o
DEPS	=	Makefile tools.h types.h self.h common.h

CC	=	gcc
CFLAGS	=	-g -O2 -Wall -W
LDFLAGS =	-lz -lgmp

OBJS	= $(COMMON) $(addsuffix .o, $(TOOLS))

all: $(TOOLS)

$(TOOLS): %: %.o $(COMMON) $(DEPS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON) $(LDFLAGS)

$(OBJS): %.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	-rm -f $(OBJS) $(TOOLS)
