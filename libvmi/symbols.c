/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2011 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
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

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "private.h"

int get_symbol_row (FILE *f, char *row, char *symbol, int position)
{
    int ret = VMI_FAILURE;

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
            ret = VMI_SUCCESS;
            break;
        }
    }

error_exit:
    if (ret == VMI_FAILURE){
        memset(row, 0, MAX_ROW_LENGTH);
    }
    return ret;
}
