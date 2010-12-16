/*
 * The findOffsets kernel module shows the kernel offset values
 * needed to configure XenAccess to work with a Linux domain.
 * 
 * Copyright (C) Nilushan Silva and Bryan D. Payne
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
 * File: findOffsets.c
 *
 * Author(s): Nilushan Silva
 *   -- initial implementation
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 *   -- cleanup and prep for distribution
 */

#include <linux/module.h>  
#include <linux/kernel.h>  
#include <linux/init.h>  
#include <linux/sched.h>  

#define MYMODNAME "FindOffsets "

static int my_init_module(void);
static void my_cleanup_module(void);


static int my_init_module(void)
{
    struct task_struct *p = NULL;
    unsigned long commOffset;
    unsigned long tasksOffset;
    unsigned long mmOffset;
    unsigned long pidOffset;
    unsigned long pgdOffset;
    unsigned long addrOffset;
   
	printk(KERN_ALERT "Module %s loaded.\n\n", MYMODNAME);
    p = current;
    if (p != NULL){
        commOffset = (unsigned long)(&(p->comm)) - (unsigned long)(p);           
        tasksOffset = (unsigned long)(&(p->tasks)) - (unsigned long)(p);           
        mmOffset = (unsigned long)(&(p->mm)) - (unsigned long)(p);           
        pidOffset = (unsigned long)(&(p->pid)) - (unsigned long)(p);           
        pgdOffset = (unsigned long)( &(p->mm->pgd) ) - (unsigned long)(p->mm);           
        addrOffset = (unsigned long)( &(p->mm->start_code) ) - (unsigned long)(p->mm);           

        printk(KERN_ALERT "[domain name] {\n");
        printk(KERN_ALERT "    ostype = \"Linux\";\n");           
        printk(KERN_ALERT "    sysmap = \"[insert path here]\";\n");           
        printk(KERN_ALERT "#    linux_name = 0x%x;\n", (unsigned int) commOffset);           
        printk(KERN_ALERT "    linux_tasks = 0x%x;\n", (unsigned int) tasksOffset); 
        printk(KERN_ALERT "    linux_mm = 0x%x;\n", (unsigned int) mmOffset); 
        printk(KERN_ALERT "    linux_pid = 0x%x;\n", (unsigned int) pidOffset); 
        printk(KERN_ALERT "    linux_pgd = 0x%x;\n", (unsigned int) pgdOffset); 
        printk(KERN_ALERT "    linux_addr = 0x%x;\n", (unsigned int) addrOffset); 
        printk(KERN_ALERT "}\n");
    }
    else{
        printk(KERN_ALERT "%s: found no process to populate task_struct.\n", MYMODNAME);
    }

    return 0;
}

static void my_cleanup_module(void)
{
    printk(KERN_ALERT "Module %s unloaded.\n", MYMODNAME);
}

module_init(my_init_module);
module_exit(my_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nilushan Silva");
MODULE_DESCRIPTION("task_struct offset Finder");
