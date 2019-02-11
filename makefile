IDIR =include
CC=g++
CFLAGS=-I $(IDIR)

ODIR=obj

SRC=src

_DEPS = 
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = main.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: $(SRC)/%.c $(DEPS)
	mkdir -p -- $(ODIR)
	$(CC) -c -o $@ $< $(CFLAGS)

fend: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -rf $(ODIR) fend