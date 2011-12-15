/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
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

#include "libvmi.h"
#include "private.h"

// Code below modified from the Handbook of Exact String-Matching Algorithms by
// Christian Charras and Thierry Lecroq.
// http://igm.univ-mlv.fr/~lecroq/string/node14.html#SECTION00140

// ASIZE = alphabet size = 256 for arbitrary bytes
#define ASIZE 256

// XSIZE = pattern size = will need to be passed as input

#ifndef MAX
    #define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

static void preBmBc (unsigned char *x, int m, int bmBc[]){
    int i;
 
    for (i = 0; i < ASIZE; ++i){
        bmBc[i] = m;
    }
    for (i = 0; i < m - 1; ++i){
        bmBc[x[i]] = m - i - 1;
    }
}
 
static void suffixes (unsigned char *x, int m, int *suff){
    int f, g, i;
 
    suff[m - 1] = m;
    g = m - 1;
    for (i = m - 2; i >= 0; --i){
        if (i > g && suff[i + m - 1 - f] < i - g){
            suff[i] = suff[i + m - 1 - f];
        }
        else{
            if (i < g){
                g = i;
            }
            f = i;
            while (g >= 0 && x[g] == x[g + m - 1 - f]){
                --g;
            }
            suff[i] = f - g;
        }
    }
}
 
static void preBmGs (unsigned char *x, int m, int bmGs[]){
    int i, j;
    int *suff = safe_malloc(m * sizeof(int));
 
    suffixes(x, m, suff);
 
    for (i = 0; i < m; ++i){
        bmGs[i] = m;
    }
    j = 0;
    for (i = m - 1; i >= 0; --i){
        if (suff[i] == i + 1){
            for (; j < m - 1 - i; ++j){
                if (bmGs[j] == m){
                    bmGs[j] = m - 1 - i;
                }
            }
        }
    }
    for (i = 0; i <= m - 2; ++i){
        bmGs[m - 1 - suff[i]] = m - 1 - i;
    }

    free(suff);
}
 
// x - pointer to pattern
// m - len(x)
// y - pointer to string to search
// n - len(y)
// modified to return location of first match, or -1
int boyer_moore (unsigned char *x, int m, unsigned char *y, int n){
    int i, j, bmBc[ASIZE];
    int *bmGs = safe_malloc(m * sizeof(int));
 
    /* Preprocessing */
    preBmGs(x, m, bmGs);
    preBmBc(x, m, bmBc);

    /* Searching */
    j = 0;
    while (j <= n - m){
        for (i = m - 1; i >= 0 && x[i] == y[i + j]; --i);
        if (i < 0){
            free(bmGs);
            return j;
            //j += bmGs[0]; // just returning the first match
        }
        else{
            j += MAX(bmGs[i], bmBc[y[i + j]] - m + 1 + i);
        }
    }

    free(bmGs);
    return -1;
}
