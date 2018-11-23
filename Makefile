DESTDIR ?=
PREFIX ?= /usr/local
NAME ?=
INCLUDES = -I./include
LIBS = -lpam -lcap
SRC_DIR = src
CXX = /usr/bin/gcc-4.1.3
CXX_FLAGS = -std=gnu99 -O2 -Wall

first: install

$(NAME): clean
	$(CXX) $(CXX_FLAGS) $(INCLUDES) $(LIBS) $(SRC_DIR)/configer.c $(SRC_DIR)/logger.c $(SRC_DIR)/protocol.c $(SRC_DIR)/knocker.c $(SRC_DIR)/main.c -o $(NAME)
	

library: clean
	$(CXX) -fPIC -shared $(INCLUDES) $(SRC_DIR)/client.c -o lib$(NAME).so
	

install: clean $(NAME) library
	install -m 0755 -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(NAME) $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)$(PREFIX)/lib
	install -m 0644 lib$(NAME).so $(DESTDIR)$(PREFIX)/lib

clean:
	rm -f $(NAME) lib$(NAME).so