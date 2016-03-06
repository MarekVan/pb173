# Makefile example
# Variables CC and CXX are automatically set on all UNIX systems.

# Variable settings
CXXFLAGS=-Wall -Wextraò
INCLUDES = -I/mbedtls-2.2.1/include
LIBS = -L/mbedtls-2.2.1/library -lm
LDFLAGS = -g
SOURCES_GEN=pb173/crypto.cpp
# Source and object lists for main program
SOURCES_MAIN=$(SOURCES_GEN) pb173/main.cpp
OBJECTS_MAIN=$(SOURCES_MAIN:.cpp=.o)
# Source and object lists for testing binary
SOURCES_TEST=$(SOURCES_GEN) pb173/testing.cpp
OBJECTS_TEST=$(SOURCES_TEST:.cpp=.o)


# Most frequently used automatic variables:
# $@ (name of the target rule)
# $< (name of the first prerequisite)
# $^ (name of all the prerequisites)

# Target anatomy:
# name: dependency1 dependency2
# <tab> command to run
# <tab> other command to run

# Target 'all' has 'main' and 'main-test' as dependencies.
# It is the first defined target (so it's run if no target is specified from CLI).
all: main main-test

# Depends on main-test, runs the test program.
test: main-test
	./main-test

# Depends on all object files and main, links the final binary.
main: $(OBJECTS_MAIN)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(LIBS) $(LDFLAGS) -o $@ $^

# Depends on all object files and test, links the test binary.
main-test: $(OBJECTS_TEST)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(LIBS) $(LDFLAGS) -o $@ $^

# Automatic rule for all object files in build directory
%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(LIBS) $(LDFLAGS) -c -o $@ $<

clean:
	rm -fr $(OBJECTS_MAIN) $(OBJECTS_TEST)
