all: calc

calc.tab.c : calc.y
	bison -d -Wno-yacc calc.y   # Generates y.tab.c and y.tab.h

lex.yy.c : calc.l
	flex calc.l       # Generates lex.yy.c

calc: calc.tab.c lex.yy.c condition_parser_mem.o
	gcc -o calc calc.tab.c lex.yy.c condition_parser_mem.o -lfl  # Compiles the generated C files and links with the Flex library

condition_parser_mem.o : condition_parser_mem.c
	gcc -c condition_parser_mem.c -o condition_parser_mem.o

clean:
	rm -f *.o calc lex.yy.c lex.yy.h y.tab.c calc.tab.c calc.tab.h condition_parser_mem.o
