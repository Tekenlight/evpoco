%code requires {

#define YY_DECL int yylex (YYSTYPE * yylval_param , yyscan_t yyscanner, parsed_output_t output)
#include "condition_parser_mem.h"

typedef void* yyscan_t;

}

%define api.pure full
%define api.push-pull pull

/*%locations */

%{
#include "calc.tab.h"  // Include the Bison-generated header file
#include "lex.yy.h"    // Include the Flex-generated header file for yyscan_t
extern void yyerror(yyscan_t scanner, parsed_output_t output, const char *s);
extern int yylex (YYSTYPE * yylval_param , yyscan_t yyscanner, parsed_output_t output);
%}

%parse-param { yyscan_t scanner } { parsed_output_t output } 
%lex-param   { yyscan_t scanner } { parsed_output_t output }

%union {
    int  ival;
    cond_mem_node_t nval;
}

%token BVALUE AND OR NOT LPAREN RPAREN NEWLINE VARIABLE CONSTANT COMPARATOR END
/*%token BVALUE AND OR NOT LPAREN RPAREN NEWLINE VARIABLE CONSTANT EQ NEQ GE LE GT LT */

%left NOT AND OR

%type <nval> expr;
%type <nval> BVALUE;
%type <nval> VARIABLE;
%type <nval> CONSTANT;
%type <nval> COMPARATOR;

%%

input:
    /* empty */
    | input line
    ;

line:
    NEWLINE
    | expr NEWLINE  { store_output(output, ($1)->buf); free_dup_buf(output, $1); YYACCEPT; }
    | expr END  { store_output(output, ($1)->buf); free_dup_buf(output, $1); YYACCEPT; }
    | error NEWLINE { puts("ERROR"); reset_output(output); yyerrok; }
    ;

expr:
    BVALUE
                    { $$ = create_output_buf(output, ($1)->buf, NULL, NULL); free_dup_buf(output, $1); }
    | CONSTANT
                    { $$ = create_output_buf(output, ($1)->buf, NULL, NULL); free_dup_buf(output, $1); }
    | VARIABLE
                    { $$ = create_output_buf(output, ($1)->buf, NULL, NULL); free_dup_buf(output, $1); }
    | VARIABLE COMPARATOR CONSTANT 
                    { $$ = create_output_buf(output, ($1)->buf, ($2)->buf, ($3)->buf); free_dup_bufs(output, $1, $2, $3); }
    | VARIABLE COMPARATOR VARIABLE
                    { $$ = create_output_buf(output, ($1)->buf, ($2)->buf, ($3)->buf); free_dup_bufs(output, $1, $2, $3); }
    | CONSTANT COMPARATOR VARIABLE
                    { $$ = create_output_buf(output, ($1)->buf, ($2)->buf, ($3)->buf); free_dup_bufs(output, $1, $2, $3); }
    | expr AND expr
                    { $$ = create_output_buf(output, ($1)->buf, "and", ($3)->buf); free_dup_bufs(output, $1, $3, NULL); }
    | expr OR expr
                    { $$ = create_output_buf(output, ($1)->buf, "or", ($3)->buf); free_dup_bufs(output, $1, $3, NULL); }
    | NOT expr
                    { $$ = create_output_buf(output, "not", ($2)->buf, NULL); free_dup_buf(output, $2); }
    | LPAREN expr RPAREN  
                    { $$ = create_output_buf(output, "(", ($2)->buf, ")"); free_dup_buf(output, $2); }
    ;


%%

void yyerror(yyscan_t scanner, parsed_output_t output, const char *s) {
    char * b = yyget_lval(scanner)->nval->buf;
    char * t = yyget_text(scanner);
    fprintf(stderr, "Error: %s [%s]\n", s, (t)?t:"??");
}

int main(int argc, char **argv) {
    parsed_output_t output = new_parsed_output();
    yyscan_t scanner;
    yylex_init(&scanner);
    printf("Enter expressions to calculate (Ctrl+D to exit):\n");
    YY_BUFFER_STATE b = yy_scan_string("true and (false or not(false))", scanner);
    printf("Calculating value of true and (false or not(false))\n");
    yyparse(scanner, output);
    printf("OUTPUT = [%s]\n", output->buffer);
    yy_delete_buffer(b, scanner);
    yylex_destroy(scanner);
    destroy_output(output);
    return 0;
}

