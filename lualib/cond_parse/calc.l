%{
#define YY_DECL int yylex (YYSTYPE * yylval_param , yyscan_t yyscanner, parsed_output_t output)
#include "condition_parser_mem.h"
#include "calc.tab.h"  // Include the Bison header file generated from the Bison file
%}

%option noyywrap
%option reentrant
%option bison-bridge
%option header-file="lex.yy.h"

%%

"false"                     { yylval_param->nval = alloc_const(output, "false"); return BVALUE; }
"true"                      { yylval_param->nval = alloc_const(output, "true"); return BVALUE; }
[0-9]+                      { yylval_param->nval = alloc_const(output, yytext); return CONSTANT; }
\'[^\']*\'                  { yylval_param->nval = alloc_const(output, yytext); return CONSTANT; }
"[0-9]*\.[0-9]+"            { yylval_param->nval = alloc_const(output, yytext); return CONSTANT; }
"and"                       { return AND; }
"or"                        { return OR; }
"not"                       { return NOT; }
"=="                        { yylval_param->nval = alloc_dupbuf(output, yytext); return COMPARATOR; }
"~="                        { yylval_param->nval = alloc_dupbuf(output, yytext); return COMPARATOR; }
">"                         { yylval_param->nval = alloc_dupbuf(output, yytext); return COMPARATOR; }
">="                        { yylval_param->nval = alloc_dupbuf(output, yytext); return COMPARATOR; }
"<"                         { yylval_param->nval = alloc_dupbuf(output, yytext); return COMPARATOR; }
"<="                        { yylval_param->nval = alloc_dupbuf(output, yytext); return COMPARATOR; }
"("                         { return LPAREN; }
")"                         { return RPAREN; }
"\n"                        { return NEWLINE; }
[_a-zA-Z][_a-zA-Z0-9]*      { yylval_param->nval = alloc_var(output, yytext); return VARIABLE; }
[ \t\r]+                    { /* ignore whitespace */ }
.                           { return YYUNDEF; }

%%


