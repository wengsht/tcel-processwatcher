MYSQL_LIB_NAME = libtpw_mysql.a
SHARED_LIB_NAME = libimareader.so
INCLUDE_DIR = ../include
CFLAGS = -Wall -I$(INCLUDE_DIR)
SEARCHGLIB = `pkg-config --cflags --libs glib-2.0`

all: $(SHARED_LIB_NAME) $(MYSQL_LIB_NAME)

$(SHARED_LIB_NAME): ima_reader_api.o
	gcc -shared $(CFLAGS) $? -o $@ $(SEARCHGLIB)

$(MYSQL_LIB_NAME): tpw_mysql.o
	ar crs $@ $?

tpw_mysql.o: tpw_mysql.c $(INCLUDE_DIR)/tpw_mysql.h
	gcc -c tpw_mysql.c -o $@ $(CFLAGS)

ima_reader_api.o: ima_reader_api.c $(INCLUDE_DIR)/ima_reader_api.h
	gcc -fPIC -c ima_reader_api.c $(CFLAGS) -o $@ $(SEARCHGLIB)

install:
	cp $(SHARED_LIB_NAME) /usr/lib/
	cp libcryptoman.so /lib

clean:
	@echo "cleaning..."
	@rm *.o
	@rm *.so
	@rm libtpw_mysql.a
	@echo "success cleaned!"
