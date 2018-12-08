#CXXFLAGS = -Wall -Wextra -g                    
#CXX = g++
#DEL=rm

#SRCS=mainprog.cpp salsa20.cpp
#OBJS=$(subst .cpp,.o,$(SRCS))
#EXEC = salsa_main

#salsa: mainprog.o salsa20.o
#	$(CXX) $(CXXFLAGS) -o $(EXEC) $(OBJS)

#mainprog.o: mainprog.cpp
#	$(CXX) -c mainprog.cpp $(CXXFLAGS)

#salsa20.o: salsa20.cpp
#	$(CXX) -c salsa20.cpp $(CXXFLAGS)

#clean:
#	$(DEL) $(OBJS)
#	$(DEL) $(EXEC)


# universal makefile from https://stackoverflow.com/a/28663974/9986282

appname := salsa

CXX := g++
CXXFLAGS := -Wall -Wextra -g
LDFLAGS :=
LDLIBS :=

srcext := cpp
srcfiles := $(shell find . -name "*.$(srcext)")
objects  := $(patsubst %.$(srcext), %.o, $(srcfiles))

all: $(appname)

$(appname): $(objects)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(appname) $(objects) $(LDLIBS)

depend: .depend

.depend: $(srcfiles)
	rm -f ./.depend
	$(CXX) $(CXXFLAGS) -MM $^>>./.depend;

clean:
	rm -f $(objects) $(appname)

#dist-clean: clean
#	rm -f *~ .depend

include .depend
