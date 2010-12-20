/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "private.h"

int get_symbol_row (FILE *f, char *row, char *symbol, int position)
{
    int ret = XA_FAILURE;

    while (fgets(row, MAX_ROW_LENGTH, f) != NULL){
        char *token = NULL;

        /* find the correct token to check */
        int curpos = 0;
        int position_copy = position;
        while (position_copy > 0 && curpos < MAX_ROW_LENGTH){
            if (isspace(row[curpos])){
                while (isspace(row[curpos])){
                    row[curpos] = '\0';
                    ++curpos;
                }
                --position_copy;
                continue;
            }
            ++curpos;
        }
        if (position_copy == 0){
            token = row + curpos;
            while (curpos < MAX_ROW_LENGTH){
                if (isspace(row[curpos])){
                    row[curpos] = '\0';
                    break;
                }
                ++curpos;
            }
        }
        else{ /* some went wrong in the loop above */
            goto error_exit;
        }

        /* check the token */
        if (strncmp(token, symbol, MAX_ROW_LENGTH) == 0){
            ret = XA_SUCCESS;
            break;
        }
    }

error_exit:
    if (ret == XA_FAILURE){
        memset(row, 0, MAX_ROW_LENGTH);
    }
    return ret;
}
