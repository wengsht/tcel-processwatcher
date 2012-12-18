KERNEL_SOURCE := /lib/modules/$(shell uname -r)/source/usr

DEMO_NAME = process_watch
MAIN = process_watch_start
INCLUDE_DIR = ../include
LIB_DIR = ../lib
IMA_READER_LIB_NAME = imareader
TSPI_UTIL_LIB_NAME = tspi_utils
MYSQL_LIB_NAME = tpw_mysql
CPPFLAGS := -I$(KERNEL_SOURCE)/include -D_GNU_SOURCE 
CFLAGS := -g -Wall -W -Wextra -O2 -I$(INCLUDE_DIR) -L$(LIB_DIR) `pkg-config --cflags --libs glib-2.0`
LDFLAGS := $(CFLAGS) -l$(IMA_READER_LIB_NAME) -lcryptoman -ltspi_utils -ltspi -ltpw_mysql -lmysqlclient

all: $(DEMO_NAME) tcel_setuser

tcel_setuser: tcel_setuser.c
	gcc tcel_setuser.c -o $@ $(LDFLAGS)

$(DEMO_NAME): $(MAIN).o fanotify_func.o $(LIB_DIR)/lib$(IMA_READER_LIB_NAME).a $(LIB_DIR)/lib$(TSPI_UTIL_LIB_NAME).a $(LIB_DIR)/lib$(MYSQL_LIB_NAME).a
	gcc $(MAIN).o fanotify_func.o -o $@ $(LDFLAGS)

$(MAIN).o: $(MAIN).c 
	gcc -c $(MAIN).c -o $@ $(CFLAGS) $(CPPFLAGS)

fanotify_func.o: fanotify_func.c
	gcc -c $? -o $@ $(CFLAGS) $(CPPFLAGS)

$(LIB_DIR)/lib$(IMA_READER_LIB_NAME).a:
	@echo "building ima_reader lib..."
	make -C $(LIB_DIR)
	@echo "install ima_reader lib..."
	sudo make -C $(LIB_DIR) install
	@echo "ima_reader install done"

$(LIB_DIR)/lib$(MYSQL_LIB_NAME).a:
	@echo "building mysql lib..."
	make -C $(LIB_DIR)
	@echo "mysql lib built done"

clean:
	rm -f $(MAIN) *.o *.orig *.rej process_watch tcel_setuser
