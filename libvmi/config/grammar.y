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
 * Definition of grammar for the configuration file.
 *
 * File: grammar.y
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include "config_parser.h"

#ifdef XA_DEBUG
#define YYERROR_VERBOSE 1
#define true 1
#define false 0

int debug = 0;
#endif /* XA_DEBUG */

xa_config_entry_t entry;
xa_config_entry_t tmp_entry;
char *target_domain = NULL;
char tmp_str[CONFIG_STR_LENGTH];

#ifdef XA_DEBUG
extern FILE *yyin;
static int eof = 0;
static int nRow = 0;
static int nBuffer = 0;
static int lBuffer = 0;
static int nTokenStart = 0;
static int nTokenLength = 0;
static int nTokenNextStart = 0;
static int lMaxBuffer = 1000;
static char *buffer = NULL;

void printError (const char *errorstring, ...)
{
    static char errmsg[10000];
    va_list args;

    int start=nTokenStart;
    int end=start + nTokenLength - 1;
    int i;

    if (eof){
        fprintf(stdout, "...... !");
        for (i = 0; i < lBuffer; ++i){
            fprintf(stdout, ".");
        }
        fprintf(stdout, "^-EOF\n");
    }
    else{
        fprintf(stdout, "...... !");
        for (i = 1; i < start; ++i){
            fprintf(stdout, ".");
        }
        for (i = start; i <= end; ++i){
            fprintf(stdout, "^");
        }
        for (i = end + 1; i < lBuffer; ++i){
            fprintf(stdout, ".");
        }
        fprintf(stdout, "   token%d:%d\n", start, end);
    }

    va_start(args, errorstring);
    vsprintf(errmsg, errorstring, args);
    va_end(args);

    fprintf(stdout, "Error: %s\n", errmsg);
}

static char dumpChar(char c)
{
    if (isprint(c)){
        return c;
    }
    return '@';
}

static char* dumpString (char *s)
{
    static char buf[101];
    int i;
    int n = strlen(s);

    if (n > 100){
        n = 100;
    }

    for (i = 0; i < n; ++i){
        buf[i] = dumpChar(s[i]);
    }
    buf[i] = 0;
    return buf;
}

void DumpRow (void)
{
    if (nRow == 0){
        int i;
        fprintf(stdout, "       |");
        for (i=1; i<71; i++){
            if (i % 10 == 0){
                fprintf(stdout, ":");
            } 
            else if (i % 5 == 0){
                fprintf(stdout, "+"); 
            }
            else{
                fprintf(stdout, ".");
            }
            fprintf(stdout, "\n"); 
        }
    }
    else{ 
        fprintf(stdout, "%6d |%.*s", nRow, lBuffer, buffer);
    }
}

static int getNextLine (void)
{
    int i;
    char *p;
    nBuffer = 0;
    nTokenStart = -1;
    nTokenNextStart = 1;
    eof = false;

    /* read a line */
    if (NULL == buffer){
        buffer = malloc(lMaxBuffer);
    }
    p = fgets(buffer, lMaxBuffer, yyin);
    if (p == NULL) {
        if (ferror(yyin)){
            return -1;
        }
        eof = true;
        return 1;
    }

    nRow += 1;
    lBuffer = strlen(buffer);
    DumpRow();

    return 0;
}

int GetNextChar (char *b, int maxBuffer)
{
    int frc;
  
    if (eof){
        return 0;
    }
  
    /* read next line if at the end of the current */
    while (nBuffer >= lBuffer){
        frc = getNextLine();
        if (frc != 0){
            return 0;
        }
    }

    /* ok, return character */
    b[0] = buffer[nBuffer];
    nBuffer += 1;

    if (debug){
        printf("GetNextChar() => '%c'0x%02x at %d\n",
                        dumpChar(b[0]), b[0], nBuffer);
    }
    return b[0]==0?0:1;
}

void BeginToken (char *t)
{
    /* remember last read token */
    nTokenStart = nTokenNextStart;
    nTokenLength = strlen(t);
    nTokenNextStart = nBuffer; // + 1;
}

#else /* !XA_DEBUG */

int GetNextChar (char *b, int maxBuffer) { return 0; }
void BeginToken (char *t) {}

#endif /* XA_DEBUG */

void yyerror (const char *str)
{
#ifndef XA_DEBUG
    fprintf(stderr,"error: %s\n",str);
#else
    printError(str);
#endif
}
 
int yywrap()
{
    return 1;
}

void entry_done ()
{
    if (strncmp(tmp_entry.domain_name, target_domain, CONFIG_STR_LENGTH) == 0){
        entry = tmp_entry;
/*
        memcpy(entry.domain_name, tmp_entry.domain_name, CONFIG_STR_LENGTH);
        memcpy(entry.sysmap, tmp_entry.sysmap, CONFIG_STR_LENGTH);
        memcpy(entry.ostype, tmp_entry.ostype, CONFIG_STR_LENGTH)
        entry.offsets = tmp_entry.offsets;
*/
    }
    bzero(&tmp_entry, sizeof(xa_config_entry_t));
}

xa_config_entry_t* xa_get_config()
{
    return &entry;
}
  
int xa_parse_config (char *td)
{
    int ret;
    target_domain = strdup(td);
    bzero(&entry, sizeof(xa_config_entry_t));
    bzero(&tmp_entry, sizeof(xa_config_entry_t));
    ret = yyparse();
    if (target_domain) free(target_domain);
    return ret;
} 

%}

%union{
    char *str;
}

%token<str>    NUM
%token         LINUX_TASKS
%token         LINUX_MM
%token         LINUX_PID
%token         LINUX_NAME
%token         LINUX_PGD
%token         LINUX_ADDR
%token         WIN_NTOSKRNL
%token         WIN_TASKS
%token         WIN_PDBASE
%token         WIN_PID
%token         WIN_PEB
%token         WIN_IBA
%token         WIN_PH
%token         SYSMAPTOK
%token         OSTYPETOK
%token<str>    WORD
%token<str>    FILENAME
%token         QUOTE
%token         OBRACE
%token         EBRACE
%token         SEMICOLON
%token         EQUALS

%%
domains:
        |
        domains domain_info
        ;

domain_info:
        WORD OBRACE assignments EBRACE
        {
            snprintf(tmp_str, CONFIG_STR_LENGTH,"%s", $1);
            memcpy(tmp_entry.domain_name, tmp_str, CONFIG_STR_LENGTH);
            entry_done();
        }
        ;

assignments:
        |
        assignments assignment SEMICOLON
        ;

assignment:
        |
        sysmap_assignment
        |
        ostype_assignment
        |
        linux_tasks_assignment
        |
        linux_mm_assignment
        |
        linux_pid_assignment
        |
        linux_pgd_assignment
        |
        linux_addr_assignment
        |
        win_ntoskrnl_assignment
        |
        win_tasks_assignment
        |
        win_pdbase_assignment
        |
        win_pid_assignment
        |
        win_peb_assignment
        |
        win_iba_assignment
        |
        win_ph_assignment
        ;

linux_tasks_assignment:
        LINUX_TASKS EQUALS NUM
        {
            int tmp = strtol($3, NULL, 0);
            tmp_entry.offsets.linux_offsets.tasks = tmp;
        }
        ;

linux_mm_assignment:
        LINUX_MM EQUALS NUM
        {
            int tmp = strtol($3, NULL, 0);
            tmp_entry.offsets.linux_offsets.mm = tmp;
        }
        ;

linux_pid_assignment:
        LINUX_PID EQUALS NUM
        {
            int tmp = strtol($3, NULL, 0);
            tmp_entry.offsets.linux_offsets.pid = tmp;
        }
        ;

linux_pgd_assignment:
        LINUX_PGD EQUALS NUM
        {
            int tmp = strtol($3, NULL, 0);
            tmp_entry.offsets.linux_offsets.pgd = tmp;
        }
        ;

linux_addr_assignment:
        LINUX_ADDR EQUALS NUM
        {
            int tmp = strtol($3, NULL, 0);
            tmp_entry.offsets.linux_offsets.addr = tmp;
        }
        ;

win_ntoskrnl_assignment:
        WIN_NTOSKRNL EQUALS NUM
        {
            int tmp = strtol($3, NULL, 0);
            tmp_entry.offsets.windows_offsets.ntoskrnl = tmp;
        }
        ;

win_tasks_assignment:
        WIN_TASKS EQUALS NUM
        {
            int tmp = strtol($3, NULL, 0);
            tmp_entry.offsets.windows_offsets.tasks = tmp;
        }
        ;

win_pdbase_assignment:
        WIN_PDBASE EQUALS NUM
        {
            int tmp = strtol($3, NULL, 0);
            tmp_entry.offsets.windows_offsets.pdbase = tmp;
        }
        ;

win_pid_assignment:
        WIN_PID EQUALS NUM
        {
            int tmp = strtol($3, NULL, 0);
            tmp_entry.offsets.windows_offsets.pid = tmp;
        }
        ;

win_peb_assignment:
        WIN_PEB EQUALS NUM
        {
            int tmp = strtol($3, NULL, 0);
            tmp_entry.offsets.windows_offsets.peb = tmp;
        }
        ;

win_iba_assignment:
        WIN_IBA EQUALS NUM
        {
            int tmp = strtol($3, NULL, 0);
            tmp_entry.offsets.windows_offsets.iba = tmp;
        }
        ;

win_ph_assignment:
        WIN_PH EQUALS NUM
        {
            int tmp = strtol($3, NULL, 0);
            tmp_entry.offsets.windows_offsets.ph = tmp;
        }
        ;

sysmap_assignment:
        SYSMAPTOK EQUALS QUOTE FILENAME QUOTE 
        {
            snprintf(tmp_str, CONFIG_STR_LENGTH,"%s", $4);
            memcpy(tmp_entry.sysmap, tmp_str, CONFIG_STR_LENGTH);
        }
        ;

ostype_assignment:
        OSTYPETOK EQUALS QUOTE WORD QUOTE 
        {
            snprintf(tmp_str, CONFIG_STR_LENGTH,"%s", $4);
            memcpy(tmp_entry.ostype, tmp_str, CONFIG_STR_LENGTH);
        }
        ;
%%
