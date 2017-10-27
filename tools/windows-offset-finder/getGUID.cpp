/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Daniel English and John Maccini
 *
 * This file is part of LibVMI.
 *
 * ---
 * This program examines a memory image for a valid Windows kernel and
 * retrieves the information needed to download a PDB symbol file from
 * Microsoft. It is confirmed to work for Windows XP, Server 2003, Vista,
 * Server 2008, and 7. Partial functionality exists for Windows 2000
 * (can display the GUID, but since most Winows 2000 kernels use a .dbg
 * file instead of .pdb, this program is unable to show the filename).
 *
 * In normal mode the program will also attempt to display the OS version
 * in use; however due to Microsoft's major/minor version numbers, it is
 * unable to distinguish between Windows Server 2003 and Windows Vista.
 *
 * getGUID is pipe-friendly with an optional -p flag. In this mode, only
 * the GUID and PDB name will be displayed for use by another program,
 * downloadPDB.py.
 *
 * See README file for more information.
 * ---
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

#include <string>
#include <stdlib.h>
#include <iostream>
#include <iomanip>
#include <fstream>

//#define DEBUG;

using namespace std;

char* getGUID(char*filename, int addr);
int checkExport(char* file, int kernbase, int fileHeaderAddr);
void printGUID(char* file, int guidStart);

/* Read null-terminated string from file at addr.
 * Will terminate if string becomes longer than 50 characters to prevent
 * freezes. */
char* memRead_str(char* file, int addr)
{
    fstream f (file, fstream::in);
    string output;
    int count = 0;

    f.seekg(addr);

    int input = f.get();
    while (input != '\0') {
        count++;
        output += input;
        input = f.get();
        if (count > 50) {
            break;
        }
    }
    //cout << output << endl;
    f.close();

    return const_cast<char*>(output.c_str());
}


//read 4 bytes from file at addr
unsigned int memRead_4(char* file, int addr)
{
    FILE *f = fopen(file, "rb");

    unsigned long int input = 0;
    if ( f != NULL ) {
        fseek(f, addr, SEEK_SET);
        fread(&input, sizeof(input), 1, f);
    }

    fclose(f);
    return input;
}

//read 2 bytes from file at addr
unsigned int memRead_2(char* file, int addr)
{
    return (memRead_4(file, addr) & 0xffff);
}

//read 1 byte from file at addr
unsigned int memRead_1(char* file, int addr)
{
    return (memRead_4(file, addr) & 0xff);
}

/* Determine whether or not the kernel begins at a given address.
 * 3 criteria are used for this:
 * A. Header must begin with 0x5a4d (Letters 'MZ')
 * B. At +60 bytes from MZ is an offset.The memory at that offset must
 * 		contain NT_SIGNATURE (00004550)
 * C. Export table name must be a valid kernel (ntoskrnl.exe, ntkrnlmp.exe, etc)
 * 		Note that this criteria is checked, but function will still return 0
 * 		(for valid kernel) no matter what the export name is. */
int validKernel(char* file, int addr)
{
    int offset;
    if (memRead_2(file, addr) == 0x5a4d) {
#ifdef DEBUG
        printf("%.8x is a valid DOS header\n", addr);
#endif
        offset = memRead_2(file, addr+60);
        offset = offset & 0xffff;
#ifdef DEBUG
        printf("offset %.8x contains %.4x\n", addr+60, memRead_4(file, addr+60));
        printf("value at %.8x: %.8x\n", addr+offset, memRead_4(file, addr+offset));
#endif
        if ((memRead_4(file, addr+offset) & 0xffffffff) == 0x00004550) {
#ifdef DEBUG
            printf("%.8x is a valid NT SIGNATURE\n", addr+60);
#endif
            if (checkExport(file, addr,addr+offset+4) == 0) {
                return 0;
            }
        }
    }


    return 1;
}
//Check the export table and display the name of the exe file.
//returns 0 if valid kernel and 1 otherwise.
int check_OS(int majVer,int minVer)
{
    switch (majVer) {
        case 3:
            if (minVer == 1)
                printf("OS version: Windows_NT_3.1\n");
            if (minVer == 5)
                printf("OS version: Windows_NT_3.5\n");
            break;
        case 4:
            printf("OS version: Windows_NT_4.0\n");
            break;
        case 5:
            if (minVer == 0)
                printf("OS version: Windows_2000\n");
            if (minVer == 1)
                printf("OS version: Windows_XP\n");
            if (minVer == 2)
                printf("OS version: Windows_Server_2003\n");
            break;
        case 6:
            if (minVer == 0)
                printf("OS version: Windows_Vista_or_Server_2008\n");
            if (minVer == 1)
                printf("OS version: Windows_7\n");
            if (minVer == 2)
                printf("OS version: Windows_8?\n");
            break;
        default:
            printf("OS version unknown or not Windows\n");

    }
    return 0;
}
int checkExport(char* file, int kernbase, int fileHeaderAddr)
{
    int exportRelAddr;
    /* Note: See findDebug section for more detailed descriptions of
     * several of these elements. */

    //Optional header at +20 bytes from file header
    int optHeaderAddr = fileHeaderAddr+20;

    /* If optional header starts with 0x10b, the file is a PE32 executable;
     * if it starts with 0x20b, it is a PE32+ executable. The offsets used
     * in these formats differ. */
    int peVer = memRead_2(file, optHeaderAddr);

    if (peVer == 0x10b) { //PE32
#ifdef DEBUG
        printf("PE32 file\n");
#endif
        /* Similar to the debug RVA located in findDebug. The export table RVA
         * should appear at a 96 byte offset from optional header start.*/
        exportRelAddr = optHeaderAddr+96;
    } else if (peVer == 0x20b) { //PE32+
#ifdef DEBUG
        printf("PE32+ file\n");
#endif
        /* Similar to the debug RVA located in findDebug. The export table RVA
         * should appear at a 112 byte offset from optional header start.*/
        exportRelAddr = optHeaderAddr+112;
    } else {
        printf("Error, not a PE file\n");
        return 1;
    }

    /* RVA is translated to a physical address by adding to the kernel base.
     * As with the debug information, there could be an error here associated
     * with the differing section/file alignment. */
    int exportAddr = kernbase+memRead_4(file, exportRelAddr);

    /* RVA to the name of the file is located at a 12 byte offset from the
     * export table start. */
    int nameAddr = memRead_4(file, exportAddr+12);

    string name = memRead_str(file, kernbase+nameAddr);
#ifdef DEBUG
    printf("\n***Check export***\n");
    //printf("kernbase: %.8x\n", kernbase);

    //Translate the name RVA to physical address and display
    cout<< name<<endl;
#endif
    if (name.compare("ntoskrnl.exe") == 0) {
        return 0;
    }

    return 1;
}

/* Find the debug information in a PE file starting at kernAddr.
 * Note that much of the information used to create this function came
 * from the Microsoft specification at:
 *  http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx
 */
void findDebug(char* file, int kernAddr) //kernel base address
{
    int imageBase;
    int imageBase2;
    int debugAddr;
    int debugRVA;
    int loadconfigaddr;
    int loadconfigRVA;

    //location of NT_SIGNATURE
    int offset = memRead_2(file, kernAddr+60);

    //File header starts 4 bytes after NT_SIGNATURE
    int fileHeaderAddr = kernAddr+offset+4;

    //Time/Date stamp is used for Win2k GUID (Time/Date, SizeOfImage)
    int timeDate = memRead_4(file, fileHeaderAddr+4);

    //File header is 20 bytes, so Optional header starts 20 bytes after file header.
    int optHeaderAddr = fileHeaderAddr + 20;

    int sectionStart = memRead_4(file, optHeaderAddr+60);

    int majVer = memRead_2(file, optHeaderAddr+40);
    int minVer = memRead_2(file, optHeaderAddr+42);
    check_OS(majVer,minVer);
    /* If optional header starts with 0x10b, the file is a PE32 executable;
     * if it starts with 0x20b, it is a PE32+ executable. The offsets used
     * in these formats differ. */
    int peVer = memRead_2(file, optHeaderAddr);

    //size of image, used in Win2k GUID.
    int sizeOfImage = memRead_4(file, optHeaderAddr+56);

    if (peVer == 0x10b) {
        //Image base. This might be used for translating some RVA's.
        imageBase = memRead_4(file, optHeaderAddr+28);

        //Debug RVA appears at byte offset 144 from optional header start
        debugAddr = optHeaderAddr+144;
        debugRVA = memRead_4(file, debugAddr);
        loadconfigaddr = optHeaderAddr+176;
        loadconfigRVA = memRead_4(file, loadconfigaddr);
    } else if (peVer == 0x20b) {
        //Image base. This might be used for translating some RVA's.
        //INSUFFICIENT! Need a memRead_8 for this one.
        imageBase = memRead_4(file, optHeaderAddr+24);
        imageBase2 = memRead_4(file, optHeaderAddr+28);

        //Debug RVA appears at byte offset 144 from optional header start
        debugAddr = optHeaderAddr+160;
        debugRVA = memRead_4(file, debugAddr);
        loadconfigaddr = optHeaderAddr+192;
        loadconfigRVA = memRead_4(file, loadconfigaddr);
    } else {
        printf("Error! Incorrect optional header number!\n");
        return;
    }

    /* RVA translated to physical address by adding RVA to kernel base
     * address. */
    int debugActual = kernAddr+debugRVA;
    int loadconfigActual = kernAddr+loadconfigRVA;
    /* DebugType is located at a 12 byte offset in the debug section. I've
     * seen two valid numbers here, a 2 or a 4. 2 is PDB, 4 is CodeView (.dbg)
     */
    int servicepackversion = memRead_2(file,loadconfigActual+76);
    int debugType = debugActual+12;
    if (memRead_4(file,debugType) == 0004) {
        printf("This operating system uses .dbg instead of .pdb\n");
        if (majVer == 5 && minVer == 0) {
            printf("The GUID for this OS is: %.8x%.8x\n",timeDate,sizeOfImage);
        }
        return;
    }
    /* This address points to the debug data section, which appears to
     * be the same as 'rsdsAddr' located below.
     */
    int debugPtr = memRead_4(file, debugActual+20);
    int rsdsAddr = kernAddr+debugPtr;
    //GUID starts directly after the letters "RSDS"
    int guidStart = rsdsAddr+4;

#ifdef DEBUG
    printf("\nService pack version ======== %.4x \n\n", servicepackversion);
    printf("\n***findDebug***\n");
    printf("Kernel base: %.8x\n", kernAddr);
    printf("Checking offset %.2x\n", offset);
    printf("File header starts at: %.8x\n", fileHeaderAddr);
    printf("Time/Date stamp: %.8x\n", timeDate);
    /*File header contains size of optional header (could be useful for finding
     * address to debug section, since that appears just after optional header)*/
    printf("Size of optional header: %x\n", memRead_2(file, fileHeaderAddr+16));
    printf("Optional Header starts at: %.8x\n", optHeaderAddr);

    //Calculate what the GUID would be if this is Win2k.
    printf("Win 2K GUID: %.8x%.8x\n", timeDate,sizeOfImage);
    printf("image base is: %.8x\n", imageBase);
    /* Section and file alignment. If these values are different, it may
     * be causing problems with RVA translation.
     */
    printf("Maj Ver: %.4x  Min Ver: %.4x\n", majVer,minVer);
    printf("Section Alignment: %.8x\n", memRead_4(file, optHeaderAddr+32));
    printf("File Alignment: %.8x\n", memRead_4(file, optHeaderAddr+36));
    printf("Section start: %.8x\n", imageBase+sectionStart);
    printf("Debug header at: %.8x\n", debugAddr);
    printf("Debug header value: %.8x\n", debugRVA);
    printf("Debug physical address: %.8x\n", debugActual);
    printf("Debug type: %.8x\n", memRead_4(file,debugType));
    printf("Debug data address: %.8x\n", kernAddr+debugPtr);
    printf("rsds Address: %.8x\n", rsdsAddr);
#endif
    //Call the print function to concatenate and display the GUID.
    printGUID(file, guidStart);
    printf("filename: ");
    printf("%s\n",memRead_str(file,rsdsAddr+24));

    return;
}

//retrieve GUID + Age from file starting at addr
//flag = 1 means just print number and filename
void printGUID(char* file, int guidStart)
{
    printf("\nguid: ");
    printf("%.8x", memRead_4(file, guidStart));
    printf("%.4x", memRead_2(file, guidStart+4));
    printf("%.4x", memRead_2(file, guidStart+6));
    printf("%.2x", memRead_1(file,guidStart+8));
    printf("%.2x", memRead_1(file,guidStart+9));
    printf("%.2x", memRead_1(file,guidStart+10));
    printf("%.2x", memRead_1(file,guidStart+11));
    printf("%.2x", memRead_1(file,guidStart+12));
    printf("%.2x", memRead_1(file,guidStart+13));
    printf("%.2x", memRead_1(file,guidStart+14));
    printf("%.2x", memRead_1(file,guidStart+15));
    printf("%.1x\n",  (memRead_1(file, guidStart+16) & 0xf));
}

void printHelp()
{
    printf("Usage: getGUID [options] <memory image file>\n\n");
    printf("This will examine the memory image and display the OS\n");
    printf("version, GUID and PDB file name for the image's OS.\n\n");
    printf("Options:\n");
    printf("-h\tshow this help page\n\n");
    printf("getGUID 0.1 by Daniel English and John Maccini\n\n");
}


int main(int argc, char* argv[])
{
    char* filename;
    string test;

    if (argc > 1 && (test=argv[1]).compare("-h") == 0) {
        printHelp();
        return 0;
    } else {
        filename = (char*)argv[1];
    }

    //Check for presence of filename
    if (filename == NULL) {
        printf("Please supply a filename eg: win7.dd\nUse -h for help with this program\n");
        return 0;
    }

    //Test the file
    FILE *f = fopen(filename, "rb");

    if (f==NULL) {
        printf("No such file\nUse -h for help with this program\n");
        return -1;
    }
    fclose(f);


    //For first 512MB of RAM, if the location is a valid kernel, call findDebug
    for (int i = 0; i < 536715264; i += 4096) {
        if (validKernel(filename, i) == 0) {
            findDebug(filename, i);
            return 0;
        }
    }
    printf("No Kernel found. Are you sure this is a Windows memory image?\n");
    return 0;
}
