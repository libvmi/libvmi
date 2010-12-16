%{
/*
 * The libxa library provides access to resources in domU machines.
 *
 * Copyright (C) 2005 - 2007  Bryan D. Payne (bryan@thepaynes.cc)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * --------------------
 * Definition of tokens for the configuration file.
 *
 * File: lexicon.l
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 */

#include <string.h>
#include "config_parser.h"
#include "grammar.h"

#ifdef XA_DEBUG
#define YY_INPUT(buf,result,max_size)  {\
    result = GetNextChar(buf, max_size); \
    if (  result <= 0  ) \
      result = YY_NULL; \
    }
#endif

%}

%%
linux_tasks             { BeginToken(yytext); return LINUX_TASKS; }
linux_mm                { BeginToken(yytext); return LINUX_MM; }
linux_pid               { BeginToken(yytext); return LINUX_PID; }
linux_pgd               { BeginToken(yytext); return LINUX_PGD; }
linux_addr              { BeginToken(yytext); return LINUX_ADDR; }
ntoskrnl                { BeginToken(yytext); return WIN_NTOSKRNL; }
win_tasks               { BeginToken(yytext); return WIN_TASKS; }
win_pdbase              { BeginToken(yytext); return WIN_PDBASE; }
win_pid                 { BeginToken(yytext); return WIN_PID; }
win_peb                 { BeginToken(yytext); return WIN_PEB; }
win_iba                 { BeginToken(yytext); return WIN_IBA; }
win_ph                  { BeginToken(yytext); return WIN_PH; }
sysmap                  { BeginToken(yytext); return SYSMAPTOK; }
ostype                  { BeginToken(yytext); return OSTYPETOK; }
0x[0-9a-fA-F]+|[0-9]+   {
    BeginToken(yytext);
    yylval.str = strdup(yytext);
    return NUM;
    }
[a-zA-Z][a-zA-Z0-9.-]+      {
    BeginToken(yytext);
    yylval.str = strdup(yytext);
    return WORD;
    }
[a-zA-Z0-9\/.-]+            {
    BeginToken(yytext);
    yylval.str = strdup(yytext);
    return FILENAME;
    }
\"                      { BeginToken(yytext); return QUOTE; }
\{                      { BeginToken(yytext); return OBRACE; }
\}                      { BeginToken(yytext); return EBRACE; }
;                       { BeginToken(yytext); return SEMICOLON; }
=                       { BeginToken(yytext); return EQUALS; }
\n                      /* ignore EOL */;
[ \t]+                  /* ignore whitespace */;
#[^\n]*\n               /* ignore comment lines */;
%%
