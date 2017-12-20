%{
/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include "config_parser.h"

#ifdef VMI_DEBUG
#define YYERROR_VERBOSE 1
#define true 1
#define false 0

int debug = 0;
#endif /* VMI_DEBUG */

extern int yylex (void);
extern int yyparse (void);

GHashTable *entry = NULL;
GHashTable *tmp_entry = NULL;
char *target_domain = NULL;
char tmp_str[CONFIG_STR_LENGTH];
char tmp_domain_name[CONFIG_STR_LENGTH];

#ifdef VMI_DEBUG
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
    vsnprintf(errmsg, 10000, errorstring, args);
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

#else /* !VMI_DEBUG */

int GetNextChar (char *b, int maxBuffer) { return 0; }
void BeginToken (char *t) {}

#endif /* VMI_DEBUG */

void yyerror (const char *str)
{
#ifndef VMI_DEBUG
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
    if (strncmp(tmp_domain_name, target_domain, CONFIG_STR_LENGTH) == 0){
        if (entry != NULL) {
            fprintf(stderr, "Duplicate config for %s found, using most recent\n", target_domain);
            g_hash_table_destroy(entry);
        }
        entry = tmp_entry;
    } else {
        g_hash_table_destroy(tmp_entry);
    }
    tmp_entry = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
}

GHashTable* vmi_get_config()
{
    return entry;
}

int vmi_parse_config (const char *target_name)
{
    int ret = 0;
    target_domain = strdup(target_name);
    tmp_entry = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    ret = yyparse();
    if (target_domain) free(target_domain);
    return ret;
}

%}

%union{
    char *str;
}

%token<str>    NUM
%token<str>    LINUX_TASKS
%token<str>    LINUX_MM
%token<str>    LINUX_PID
%token<str>    LINUX_NAME
%token<str>    LINUX_PGD
%token<str>    LINUX_ADDR
%token<str>    LINUX_INIT_TASK
%token<str>    WIN_NTOSKRNL
%token<str>    WIN_NTOSKRNL_VA
%token<str>    WIN_TASKS
%token<str>    WIN_PDBASE
%token<str>    WIN_PID
%token<str>    WIN_PNAME
%token<str>    WIN_KDVB
%token<str>    WIN_KDBG
%token<str>    WIN_KPCR
%token<str>    WIN_SYSPROC
%token<str>    FREEBSD_NAME
%token<str>    FREEBSD_PID
%token<str>    FREEBSD_VMSPACE
%token<str>    FREEBSD_PMAP
%token<str>    FREEBSD_PGD
%token<str>    SYSMAPTOK
%token<str>    REKALL_PROFILE
%token<str>    OSTYPETOK
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
            snprintf(tmp_str, CONFIG_STR_LENGTH, "%s", $1);
            memcpy(tmp_domain_name, tmp_str, CONFIG_STR_LENGTH);
            free($1);
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
        rekall_profile_assignment
        |
        ostype_assignment
        |
        linux_tasks_assignment
        |
        linux_mm_assignment
        |
        linux_pid_assignment
        |
        linux_name_assignment
        |
        linux_pgd_assignment
        |
        linux_addr_assignment
        |
        linux_init_task_assignment
        |
        win_ntoskrnl_assignment
        |
        win_ntoskrnl_va_assignment
        |
        win_tasks_assignment
        |
        win_pdbase_assignment
        |
        win_pid_assignment
        |
        win_pname_assignment
        |
        win_kdvb_assignment
        |
        win_kdbg_assignment
        |
        win_kpcr_assignment
        |
        win_sysproc_assignment
        |
        freebsd_name_assignment
        |
        freebsd_pid_assignment
        |
        freebsd_vmspace_assignment
        |
        freebsd_pmap_assignment
        |
        freebsd_pgd_assignment
        ;

linux_tasks_assignment:
        LINUX_TASKS EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;

linux_mm_assignment:
        LINUX_MM EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;

linux_pid_assignment:
        LINUX_PID EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;
linux_name_assignment:
        LINUX_NAME EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;

linux_pgd_assignment:
        LINUX_PGD EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;

linux_addr_assignment:
        LINUX_ADDR EQUALS NUM
        {
            fprintf(stderr, "VMI_WARNING: linux_addr is no longer used and should be removed from your config file\n");
            free($3);
        }
        ;

linux_init_task_assignment:
        LINUX_INIT_TASK EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;

win_ntoskrnl_assignment:
        WIN_NTOSKRNL EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;

win_ntoskrnl_va_assignment:
        WIN_NTOSKRNL_VA EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;

win_tasks_assignment:
        WIN_TASKS EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;

win_pdbase_assignment:
        WIN_PDBASE EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;

win_pid_assignment:
        WIN_PID EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;

win_pname_assignment:
        WIN_PNAME EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;

win_kdvb_assignment:
        WIN_KDVB EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;

win_kdbg_assignment:
        WIN_KDBG EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;

win_kpcr_assignment:
        WIN_KPCR EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;

win_sysproc_assignment:
        WIN_SYSPROC EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;

freebsd_name_assignment:
        FREEBSD_NAME EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;
freebsd_pid_assignment:
        FREEBSD_PID EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;
freebsd_vmspace_assignment:
        FREEBSD_VMSPACE EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;
freebsd_pmap_assignment:
        FREEBSD_PMAP EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;
freebsd_pgd_assignment:
        FREEBSD_PGD EQUALS NUM
        {
            uint64_t tmp = strtoull($3, NULL, 0);
            uint64_t *tmp_ptr = malloc(sizeof(uint64_t));
            (*tmp_ptr) = tmp;
            g_hash_table_insert(tmp_entry, $1, tmp_ptr);
            free($3);
        }
        ;

sysmap_assignment:
        SYSMAPTOK EQUALS QUOTE FILENAME QUOTE
        {
            snprintf(tmp_str, CONFIG_STR_LENGTH, "%s", $4);
            char* sysmap_path = strndup(tmp_str, CONFIG_STR_LENGTH);
            g_hash_table_insert(tmp_entry, $1, sysmap_path);
            free($4);
        }
        ;

rekall_profile_assignment:
        REKALL_PROFILE EQUALS QUOTE FILENAME QUOTE
        {
            snprintf(tmp_str, CONFIG_STR_LENGTH, "%s", $4);
            char* rekall_profile = strndup(tmp_str, CONFIG_STR_LENGTH);
            g_hash_table_insert(tmp_entry, $1, rekall_profile);
            free($4);
        }
        ;

ostype_assignment:
        OSTYPETOK EQUALS QUOTE WORD QUOTE
        {
            snprintf(tmp_str, CONFIG_STR_LENGTH, "%s", $4);
            char* os_type_str = strndup(tmp_str, CONFIG_STR_LENGTH);
            g_hash_table_insert(tmp_entry, $1, os_type_str);
            free($4);
        }
        ;
%%
