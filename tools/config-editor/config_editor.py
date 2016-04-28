#!/usr/bin/python
# encoding: utf-8

import signal
import sys
import os.path
import npyscreen as _nps
from configobj import ConfigObj

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
   This config_editor create well formed config text files for Libvmi
   Copyright (C) 2016 - 2017  D'Mita Levy (dlevy022@fiu.edu)
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   About This Application
   ----------------------
   Creates configuration files for LibVMI assuming one already has the VM offsets.
   More info about LibVMI and its configuration files can be found here:

    LibVMI Website: http://libvmi.com/docs/gcode-install.html

    Old Config Objects: https://code.google.com/p/xenaccess/wiki/ConfigurationEntries

    Supported Python Versions
    -------------------------
    The following Python versions have been tested and work:

    -Python version 2.7.5
    -Python version 2.7.6

    Dependencies
    -------------------------
    The only required dependencies at this time are npyscreen and configobj. The easiest way to install both is using the python setup tool easy_install and then run:

    $ sudo easy_install npyscreen

    and

    $ sudo easy_install configobj

    Known Issues
    --------------------------
    1. Resizing console window cuts off some options
    -If this happens it's best to try and resize the window again or just exit the application and restart



'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''


'''
APP GLOBAL FIELDS
'''
#current size of the vm list
_vm_list_size = 0
#list of vm objects the application knows about
_vm_list = {}

_vm_list_os_linux = 0
_vm_list_os_windows = 0

_conf_file_name ="libvmi.conf"#default
_conf_file_destination =""

#name_major.minor.patch
_version = "2.10.0" #Todo change me after every significant  update
_full_versionb = "Libvmi-Config-Editor_2.10.0" #Todo change me after every significant  update
_last_update="4/2016"#Todo change me after every significant update
#Error messages to display
ERROR_MSGS =['Invalid Option','Unexpected Error','File Access Error','Invalid Input','Virtual Machine Exists']
NOTIFY_MSGS =['Add New VM Success!','Confirm Exit']
ABOUT_MSGS = "LibVMI Configuration Editor version "+_version+"\nAuthor: D'Mita Levy\nLast Update: "+_last_update
NOTE_MSGS = ['- Press CTRL + X to navigate through the application']


def isInteger(num):
    try:
        int(num)
        return True
    except ValueError:
        try:
            int(num,16)
            return True
        except ValueError:
            return False

def error(message, msg_title):
    _nps.notify_confirm(message, title=msg_title, form_color='STANDOUT', wrap=True, wide=False)

def notify(message, msg_title):
    _nps.notify_confirm(message, title=msg_title, form_color='STANDOUT', wrap=True, wide=False)

#catch interrupts to avoid traceback
def signal_handler(signal, frame):
    _APP.error_msg("Are you sure you want to exit the application?", NOTIFY_MSGS[1])

signal.signal(signal.SIGINT, signal_handler)

def _safe_exit():
    print ""#TODO: needs to be implemented


#addas a new vm object (windows) into the list of vm's to be written to libvmi.conf
def _insert_windows_vm(name,tasks,pdbase,pid):

    global _vm_list
    global _vm_list_size
    global _vm_list_os_windows

    vm = None
    vm = _vm_list.get(name)

    #vm exists, check if the os is the same
    if vm !=None:
        if vm.os_type == "Windows":
            #ask the user if they want to write over the machine
            opt = _nps.notify_ok_cancel("A virtual machine with the name "+name+" already exists for this config. Would you like to overwrite the entry?", title=ERROR_MSGS[4])
            if opt == False:
                return
            else:
                #decrement so the list size is the same
                _vm_list_size+=-1
                _vm_list_os_windows+=-1

    vm = VM(name,"Windows")
    vm.win_tasks = tasks
    vm.win_pdbase = pdbase
    vm.win_pid = pid
    _vm_list_os_windows+=1
    _vm_list[name] = vm
    _vm_list_size+=1
    notify("Added Linux Virtual Machine: "+str(name),NOTIFY_MSGS[0])
    return True

#adds a new vm oject (linux) into the list of vm's to be written to libvmi.conf
def _insert_linux_vm(name,tasks,mm,pid,pgd,sysmap):

    global _vm_list
    global _vm_list_size
    global _vm_list_os_linux
    vm = None
    vm = _vm_list.get(name)

    #vm exists, check if the os is the same
    if vm !=None:
        if vm.os_type == "Linux":
            #ask the user if they want to write over the machine
            opt = _nps.notify_ok_cancel("A virtual machine with the name "+name+" already exists for this config. Would you like to overwrite the entry?", title=ERROR_MSGS[4])
            if opt == False:
                return
            else:
                #decrement so the list size is the same
                _vm_list_size+=-1
                _vm_list_os_linux+=-1

    vm = VM(name,"Linux")
    vm.linux_tasks = tasks
    vm.linux_mm = mm
    vm.linux_pid = pid
    vm.linux_pgd = pgd
    vm.linux_sysmap = sysmap
    _vm_list_os_linux += 1
    _vm_list[name] = vm
    _vm_list_size+=1
    notify("Added Linux Virtual Machine: "+str(name),NOTIFY_MSGS[0])
    return True


'''
NPYSCREEN Custom Widgets created for this application
'''
#clickable button that shows the form for adding a new linux vm
class Btn_AddLinux(_nps.ButtonPress):
    def whenPressed(self):
        self.parent.vm_editor('NEW_LINUX')

class Btn_WriteFile(_nps.ButtonPress):
    def whenPressed(self):
        self.parent.write_file()

class Btn_AddWindows(_nps.ButtonPress):
    def whenPressed(self):
        self.parent.vm_editor('NEW_WINDOWS')

class Btn_ConfirmVM(_nps.ButtonPress):
    def whenPressed(self):
        self.parent.add_vm()

class Btn_CancelVM(_nps.ButtonPress):
    def whenPressed(self):
        self.parent.cancel_add()

class Btn_RemoveVM(_nps.ButtonPress):
    def whenPressed(self):
        self.parent.remove_vm()

class Btn_WriteConfig(_nps.ButtonPress):
    def whenPressed(self):
        self.parent.generate_config()

class Btn_ListVM(_nps.ButtonPress):
    def whenPressed(self):
        self.parent.list_vms()

class Btn_CancelWrite(_nps.ButtonPress):
    def whenPressed(self):
        self.parent.cancel_write()

class Btn_ConfirmRemoveVM(_nps.ButtonPress):
    def whenPressed(self):
        self.parent.confirm_remove_vm()


'''
'''

class VM:

    def __init__(self,vm_name,vm_os):
        self.name = vm_name
        self.os_type = vm_os
        #for the sake of clarity we allow VM object to have both windows and Linux fields
        #the differentiation comes from explicit checking of the 'type' field
        self.linux_tasks =   None
        self.linux_mm    =   None
        self.linux_pid   =   None
        self.linux_pgd   =   None
        self.linux_sysmap   =   None
        self.win_tasks = None
        self.win_pdbase = None
        self.win_pid = None

#removes a vm from the list of existing vms
class Remove_VM_Form(_nps.ActionFormWithMenus):

    def create(self):

            #menus
            self.menu_main = self.add_menu(name="Main Menu", shortcut="m")
            self.menu_main.addItemsFromList([
            ("Home Screen", self.home, "h"),
            ("Add Windows VM", self.start_windows_vm_editor, "w"),
            ("Add Linux VM", self.start_linux_vm_editor, "t"),
            ("List All VM's", self.list_vms, "a"),
            ("Remove VM", self.remove_vm, "r"),
            ("Write File", self.start_config_writer,"z"),
            ("Close Menu", self.close_menu,"c"),
            ("About", self.display_text,None,None,(ABOUT_MSGS,)),
            ("Exit Application", self.exit_app,"x")
            ])

            self.instructions = self.add(_nps.TitleFixedText, name="Instructions: ", value="Select a virtual machine to remove it from the list")
            self.nextrely+=1
            self.vm_option    = self.add(_nps.TitleSelectOne, scroll_ext=True, max_height=10, name='Menu Options', values=[])
            self.nextrely+=1
            self.btn_list_vm = self.add(Btn_ListVM, name="List All VM's")
            self.btn_remove_vm =self.add(Btn_ConfirmRemoveVM, name="Remove VM")


    def display_text(self, argument):
        _nps.notify_confirm(argument)

    def write_file(self):
        self.parentApp.switchForm('WRITE_CONFIG')

    def list_vms(self):
        self.parentApp.switchForm('LIST_VM')

    def confirm_remove_vm(self):
        global _vm_list_size
        if _vm_list_size == 0:
            error("There are no virtual machines, please add more virtual machines",ERROR_MSGS[0])
            return

        opt = self.vm_option.get_selected_objects()

        global _vm_list
        vm = _vm_list.get(opt[0])
        #TODO individual OS count change?
        name = vm.name
        confirm = _nps.notify_ok_cancel("Are you sure you want to remove the virtual machine "+name,title="Confirm Remove VM")
        if confirm == False:
            return
        del _vm_list[opt[0]]
        _vm_list_size+=-1
        self.display_text("Removed virtual machine "+name)
        self.parentApp.switchForm('REMOVE_VM')


    def close_menu(self):
        #the menu tends to get stuck and as such this is a dirty and easy way to close it
        1+1

    def exit_app(self):
        _safe_exit()
        self.parentApp.setNextForm(None)
        self.editing = False
        self.parentApp.switchFormNow()

    def home(self):
        self.parentApp.switchForm('CONFIG')

    def start_windows_vm_editor(self):
        self.vm_editor('NEW_WINDOWS')

    def start_linux_vm_editor(self):
        self.vm_editor('NEW_LINUX')

    def start_config_writer(self):
        self.parentApp.switchForm('WRITE_CONFIG')

    def list_vms(self):
        self.parentApp.switchForm('LIST_VM')

    def remove_vm(self):
        self.parentApp.switchForm('REMOVE_VM')

    def vm_editor(self,os_type):
        #save current globals and switch
        self.parentApp.switchForm(os_type)

    def on_cancel(self):
        self.parentApp.switchFormPrevious()

    def on_ok(self):
        self.parentApp.switchForm('CONFIG')

    def beforeEditing(self):
        all_vms = []
        #build a list of vms before displaying
        for key in _vm_list:
            vm = _vm_list[key]
            vm_data = vm.name
            all_vms.append(vm_data)

        self.vm_option.values = all_vms


class Write_Config_Form(_nps.ActionFormWithMenus):

    def create(self):
        self.menu_main = self.add_menu(name="Main Menu", shortcut="m")
        self.menu_main.addItemsFromList([
        ("Home Screen", self.home, "h"),
        ("Add Windows VM", self.start_windows_vm_editor, "w"),
        ("Add Linux VM", self.start_linux_vm_editor, "t"),
        ("List All VM's", self.list_vms, "a"),
        ("Remove VM", self.remove_vm, "r"),
        ("Close Menu", self.close_menu,"c"),
        ("About", self.display_text,None,None,(ABOUT_MSGS,)),
        ("Exit Application", self.exit_app,"x")
        ])

        self.file_name = self.add(_nps.TitleText, name="File name:", value=_conf_file_name)
        self.file_destination = self.add(_nps.TitleFilename, name="Destination:", value=_conf_file_destination)
        self.vm_count = self.add(_nps.TitleFixedText, name="VM Configs:", value=str(_vm_list_size))
        self.nextrely+=1
        self.status = self.add(_nps.TitleFixedText, name="Status:", value="Waiting....please select 'Write Config File' to begin")
        self.nextrely+=1
        self.btn_remove_vm      =     self.add(Btn_WriteConfig, name="Write Config File")


    def generate_config(self):
        valid = self.validate()
        if valid:
            self.write_config()

    def home(self):
        self.parentApp.switchForm('CONFIG')


    def validate(self):
        #check if vm list is empty
        if _vm_list_size == 0:
            self.error_msg("There are no VM's...Please add VM configurations before attempting to write the config file",ERROR_MSGS[0])
            return False
        return True

    #write the config to file -ConfigObj is used to build the objects then stringified
    def write_config(self):

        config = None
        output_file = None
        global _conf_file_name
        _conf_file_name = self.file_name.value
        global _conf_file_destination
        _conf_file_destination = self.file_destination.value
        final_destination = os.path.join(_conf_file_destination,_conf_file_name)

        try:
            #check if file exists - stop if it does
            if os.path.isfile(final_destination):
                opt = _nps.notify_ok_cancel("A file with the same name already exists at this location. Would you like to add to this file?", title=ERROR_MSGS[2])
                if opt == True:
                    output_file = open(final_destination,"a")
                else:
                    return
            else:
                output_file = open(final_destination,"w")

            #from the _vm_list dict build config strings and write each to the file
            for key in _vm_list:
                config = ConfigObj(unrepr=True)
                vm = _vm_list[key]

                if vm.os_type == "Linux":
                    config['sysmap '] = "\""+vm.linux_sysmap+"\";"
                    config['ostype '] = "\""+vm.os_type+"\";"
                    config['linux_tasks '] = vm.linux_tasks+";"
                    config['linux_mm '] = vm.linux_mm+";"
                    config['linux_pid '] = vm.linux_pid+";"
                    config['linux_pgd '] = vm.linux_pgd+";"
                else:
                    config['ostype '] = "\""+vm.os_type+"\";"
                    config['win_tasks '] = vm.win_tasks+";"
                    config['win_pdbase '] = vm.win_pdbase+";"
                    config['win_pid '] = vm.win_pid+";"

                output = vm.name+" "
                output = output+str(config)
                output = output.replace("'","").replace(",","").replace(":","=")
                output = output +"\n"

                self.status.value ="Writing VM "+vm.name
                self.display()

                output_file.write(output)

            self.status.value ="Finished Writing File....Waiting..."
            self.display()
        except IOError as e:
            self.error_msg("There was an error accessing the file: "+e.detail,ERROR_MSGS[2])
            return
        finally:
            if output_file != None:
                output_file.close()

        self.display_text("Finished writing configuration file \""+_conf_file_name+"\" to desintation: "+_conf_file_destination)

    def cancel_write():
        self.parentApp.switchFormPrevious()

    def display_text(self, argument):
        _nps.notify_confirm(argument)

    def error_msg(self,message,title):
        notify(message,title)

    def exit_app(self):
        _safe_exit()
        self.parentApp.setNextForm(None)
        self.editing = False
        self.parentApp.switchFormNow()

    def start_windows_vm_editor(self):
        self.vm_editor('NEW_WINDOWS')

    def start_linux_vm_editor(self):
        self.vm_editor('NEW_LINUX')

    def remove_vm(self):
        self.parentApp.switchForm('REMOVE_VM')

    def list_vms(self):
        self.parentApp.switchForm("LIST_VM")

    def vm_editor(self,os_type):
        self.parentApp.switchForm(os_type)

    def on_cancel(self):
        self.parentApp.switchFormPrevious()

    def on_ok(self):
        self.parentApp.switchForm('CONFIG')

    def close_menu(self):
        #the menu tends to get stuck and as such this is a dirty and easy way to close it
        1+1

    def beforeEditing(self):
        self.file_name.value = _conf_file_name
        self.file_destination.value = _conf_file_destination
        self.vm_count.value = str(_vm_list_size)

#Shows the vm list for the config File
class VM_List_Form(_nps.ActionFormWithMenus):

    def create(self):
        self.menu_main = self.add_menu(name="Main Menu", shortcut="m")
        self.menu_main.addItemsFromList([
        ("Home Screen", self.home, "h"),
        ("Add Windows VM", self.start_windows_vm_editor, "w"),
        ("Add Linux VM", self.start_linux_vm_editor, "t"),
        ("List All VM's", self.list_vms, "a"),
        ("Write File", self.start_config_writer,"z"),
        ("Remove VM", self.remove_vm, "r"),
        ("Close Menu", self.close_menu,"c"),
        ("About", self.display_text,None,None,(ABOUT_MSGS,)),
        ("Exit Application", self.exit_app,"x")
        ])


        self.vm_list = self.add(_nps.TitleMultiLine, name ="VM List")

    def display_text(self, argument):
        _nps.notify_confirm(argument)

    def home(self):
        self.parentApp.switchForm('CONFIG')


    def exit_app(self):
        _safe_exit()
        self.parentApp.setNextForm(None)
        self.editing = False
        self.parentApp.switchFormNow()

    def start_config_writer(self):
        self.parentApp.switchForm('WRITE_CONFIG')

    def start_windows_vm_editor(self):
        self.vm_editor('NEW_WINDOWS')

    def start_linux_vm_editor(self):
        self.vm_editor('NEW_LINUX')

    def remove_vm(self):
        self.parentApp.switchForm('REMOVE_VM')


    def list_vms(self):
        self.parentApp.switchForm('LIST_VM')

    def vm_editor(self,os_type):
        self.parentApp.switchForm(os_type)

    def on_cancel(self):
        self.parentApp.switchFormPrevious()

    def on_ok(self):
        self.parentApp.switchForm('CONFIG')

    def close_menu(self):
        #the menu tends to get stuck and as such this is a dirty and easy way to close it
        1+1

    def beforeEditing(self):

        all_vms = []
        #build a list of vms before displaying
        for key in _vm_list:
            vm = _vm_list[key]
            vm_data = "vm: "+vm.name+" os: "+vm.os_type
            if vm.os_type =="Linux":
                vm_data +=" tasks: "+vm.linux_tasks
                vm_data +=" mm: "+vm.linux_mm
                vm_data +=" pid: "+vm.linux_pid
                vm_data +=" pgd: "+vm.linux_pgd
            else:
                vm_data +=" tasks: "+vm.win_tasks
                vm_data +=" pdbase: "+vm.win_pdbase
                vm_data +=" pid: "+vm.win_pid
            all_vms.append(vm_data)

        self.vm_list.set_values(all_vms)
        #self.vm_list.set_values([str("VM: "+key+" OS: "+_vm_list[key].os_type) for key in _vm_list])

#Allows the user to add a new Windows VM to the list of vms that will be written to libvmi.conf
class Add_Windows_Form(_nps.ActionFormWithMenus):
    vm_os = "Windows"

    def create(self):

        self.menu_main = self.add_menu(name="Main Menu", shortcut="m")
        self.menu_main.addItemsFromList([
        ("Home Screen", self.home, "h"),
        ("Add Linux VM", self.start_linux_vm_editor, "t"),
        ("List All VM's", self.list_vms, "a"),
        ("Remove VM", self.remove_vm, "r"),
        ("Write File", self.start_config_writer,"z"),
        ("Close Menu", self.close_menu,"c"),
        ("Exit Application", self.exit_app,"x"),
        ])

        self.instructions = self.add(_nps.TitleFixedText, name="Instructions:", value="Enter the Windows VM configuration information")
        self.nextrely+=1
        self.name        =     self.add(_nps.TitleText, name = "VM Name: ")
        self.win_tasks    =   self.add(_nps.TitleText, name = "Win tasks: ")
        self.win_pdbase       =   self.add(_nps.TitleText, name = "Win pdbase: ")
        self.win_pid       =   self.add(_nps.TitleText, name = "Win pid: ")
        self.nextrely+=1
        self.btn_add_vm      =     self.add(Btn_ConfirmVM, name = "Save Windows VM")
        self.btn_cancel      =     self.add(Btn_CancelVM, name = "Done")


    #inserts the new vm into the vm list
    def add_vm(self):
        if self.validate_input():
            if _insert_windows_vm(self.name.value,self.win_tasks.value,self.win_pdbase.value,self.win_pid.value) == True:
                self.clear_input()
        else:
            return
    def home(self):
        self.parentApp.switchForm('CONFIG')


    def clear_input(self):
        self.name.value=""
        self.win_tasks.value =""
        self.win_pdbase.value =""
        self.win_pid.value = ""
        self.display()

    def validate_input(self):
        if isInteger(self.win_tasks.value) == False:
            self.error_msg("The win tasks offset must be numeric - all of the offsets can be specified in either hex or decimal",ERROR_MSGS[3])
            return False
        if isInteger(self.win_pdbase.value) == False:
            self.error_msg("The win pdbase offset must be numeric - all of the offsets can be specified in either hex or decimal",ERROR_MSGS[3])
            return False
        if isInteger(self.win_pid.value) == False:
            self.error_msg("The win pid offset must be numeric - all of the offsets can be specified in either hex or decimal",ERROR_MSGS[3])

        return True

    def error_msg(self,message,title):
        notify(message,title)

    def start_linux_vm_editor(self):
        self.vm_editor('NEW_LINUX')

    def start_config_writer(self):
        self.parentApp.switchForm('WRITE_CONFIG')

    def remove_vm(self):
        self.parentApp.switchForm('REMOVE_VM')

    def list_vms(self):
        self.parentApp.switchForm("LIST_VM")

    def vm_editor(self,os_type):
        self.parentApp.switchForm(os_type)

    def cancel_add(self):
        self.parentApp.switchFormPrevious()

    def close_menu(self):
        #the menu tends to get stuck and as such this is a dirty and easy way to close it
        1+1

    def beforeEditing(self):
        self.name.value =""
        self.win_tasks.value = ""
        self.win_pdbase.value = ""
        self.win_pid.value = ""

    def on_cancel(self):
        self.parentApp.switchFormPrevious()

    def on_ok(self):
        self.parentApp.switchForm('CONFIG')

    def exit_app(self):
        _safe_exit()
        self.parentApp.setNextForm(None)
        self.editing = False
        self.parentApp.switchFormNow()



#Allows the user to add a new Linux VM to the list of vms that will be written to libvmi.conf
class Add_Linux_Form(_nps.ActionFormWithMenus):
    vm_os = "Linux"

    def create(self):

        self.menu_main = self.add_menu(name="Main Menu", shortcut="m")
        self.menu_main.addItemsFromList([
        ("Home Screen", self.home, "h"),
        ("Add Windows VM", self.start_windows_vm_editor, "w"),
        ("List All VM's", self.list_vms, "a"),
        ("Remove VM", self.start_windows_vm_editor, "r"),
        ("Write File", self.start_config_writer,"z"),
        ("Close Menu", self.close_menu,"c"),
        ("Exit Application", self.exit_app,"x")
        ])

        self.instructions = self.add(_nps.TitleFixedText, name="Instructions:", value="Enter the Linux VM configuration information")
        self.nextrely+=1
        self.name        =     self.add(_nps.TitleText, name = "VM Name: ")
        self.linux_tasks    =   self.add(_nps.TitleText, name = "Linux tasks: ")
        self.linux_mm       =   self.add(_nps.TitleText, name = "Linux mm: ")
        self.linux_pid       =   self.add(_nps.TitleText, name = "Linux pid: ")
        self.linux_pgd      =   self.add(_nps.TitleText, name = "Linux pgd: ")
        self.sysmap      =     self.add(_nps.TitleFilename, name ="Sys Map: ")
        self.nextrely+=1
        self.btn_add_vm      =     self.add(Btn_ConfirmVM, name = "Save Linux VM")
        self.btn_cancel      =     self.add(Btn_CancelVM, name = "Done")


    def start_windows_vm_editor(self):
        self.vm_editor('NEW_WINDOWS')

    def start_config_writer(self):
        self.parentApp.switchForm('WRITE_CONFIG')

    def vm_editor(self,os_type):
        #save current globals and switch
        self.parentApp.switchForm(os_type)

    def list_vms(self):
        self.parentApp.switchForm("LIST_VM")

    #inserts the new vm into the vm list
    def add_vm(self):
        if self.validate_input():
            if _insert_linux_vm(self.name.value,self.linux_tasks.value,self.linux_mm.value,self.linux_pid.value,self.linux_pgd.value,self.sysmap.value) == True:
                self.clear_input()
        else:
            return

    def clear_input(self):
        self.name.value=""
        self.linux_tasks.value=""
        self.linux_mm.value=""
        self.linux_pid.value=""
        self.linux_pgd.value=""
        self.sysmap.value=""
        self.display()


    def validate_input(self):
        if isInteger(self.linux_tasks.value) == False:
            self.error_msg("The linux tasks offset must be numeric - all of the offsets can be specified in either hex or decimal",ERROR_MSGS[3])
            return False
        if isInteger(self.linux_tasks.value) == False:
            self.error_msg("The linux mm offset must be numeric - all of the offsets can be specified in either hex or decimal",ERROR_MSGS[3])
            return False
        if isInteger(self.linux_tasks.value) == False:
            self.error_msg("The linux pid offset must be numeric - all of the offsets can be specified in either hex or decimal",ERROR_MSGS[3])
            return False
        if isInteger(self.linux_tasks.value) == False:
            self.error_msg("The linux pgd offset must be numeric - all of the offsets can be specified in either hex or decimal",ERROR_MSGS[3])
            return False

        return True

    def home(self):
        self.parentApp.switchForm('CONFIG')

    def cancel_add(self):
        self.parentApp.change_form('CONFIG')

    def close_menu(self):
        #the menu tends to get stuck and as such this is a dirty and easy way to close it
        1+1

    def error_msg(self,message,title):
        notify(message,title)

    def beforeEditing(self):
        self.name.value =""
        self.linux_tasks.value = ""
        self.linux_mm.value = ""
        self.linux_pid.value = ""
        self.linux_pgd.value = ""
        self.sysmap.value =    ""

    def on_cancel(self):
        self.parentApp.switchFormPrevious()

    def on_ok(self):
        self.parentApp.switchForm('CONFIG')

    def exit_app(self):
        _safe_exit()
        self.parentApp.setNextForm(None)
        self.editing = False
        self.parentApp.switchFormNow()



class Config_Form(_nps.ActionFormWithMenus):

    def create(self):
        #menus
        self.menu_main = self.add_menu(name="Main Menu", shortcut="m")
        self.menu_main.addItemsFromList([
        ("Home Screen", self.home, "h"),
        ("Add Windows VM", self.start_windows_vm_editor, "w"),
        ("Add Linux VM", self.start_linux_vm_editor, "t"),
        ("List All VM's", self.list_vms, "a"),
        ("Remove VM", self.remove_vm, "r"),
        ("Write File", self.start_config_writer,"z"),
        ("Close Menu", self.close_menu,"c"),
        ("About", self.display_text,None,None,(ABOUT_MSGS,)),
        ("Exit Application", self.exit_app,"x")
        ])

        self.file_name = self.add(_nps.TitleText, name="File name:", value=_conf_file_name)
        self.file_destination = self.add(_nps.TitleFilename, name="Destination:", value=_conf_file_destination)
        self.vm_count = self.add(_nps.TitleFixedText, name="VM's in File:", value=str(_vm_list_size))
        self.nextrely+=1
        self.vm_list_box = self.add(_nps.BoxTitle, name="Virtual Machines in File", max_width=35, relx=2, max_height=10, scroll_exit=True)
        self.vm_list_box.set_values([str(key) for key in _vm_list])
        self.nextrely+=2
        self.btn_add_windows    =     self.add(Btn_AddWindows, name ="Add Windows VM")
        self.btn_add_linux      =     self.add(Btn_AddLinux, name ="Add Linux VM")
        self.btn_remove_vm      =     self.add(Btn_RemoveVM, name="Remove VM")
        self.btn_write_file = self.add(Btn_WriteFile, name="Write Config File")
        self.nextrely+=1
        self.tip1 = self.add(_nps.TitleFixedText, name="Tip:", value="Press CTRL + X to navigate using the menus on the next screen")
        self.nextrely+=1

    def display_text(self, argument):
        _nps.notify_confirm(argument)

    def write_file(self):
        self.parentApp.switchForm('WRITE_CONFIG')

    def close_menu(self):
        #the menu tends to get stuck and as such this is a dirty and easy way to close it
        1+1

    def exit_app(self):
        _safe_exit()
        self.parentApp.setNextForm(None)
        self.editing = False
        self.parentApp.switchFormNow()

    def home(self):
        self.parentApp.switchForm('CONFIG')

    def start_windows_vm_editor(self):
        self.save_globals()
        self.vm_editor('NEW_WINDOWS')

    def start_linux_vm_editor(self):
        self.save_globals()
        self.vm_editor('NEW_LINUX')

    def start_config_writer(self):
        self.save_globals()
        self.parentApp.switchForm('WRITE_CONFIG')

    def list_vms(self):
        self.save_globals()
        self.parentApp.switchForm("LIST_VM")

    def remove_vm(self):
        self.save_globals()
        self.parentApp.switchForm("REMOVE_VM")

    def vm_editor(self,os_type):
        self.save_globals()
        #save current globals and switch
        self.parentApp.switchForm(os_type)

    def save_globals(self):
        global _conf_file_name
        _conf_file_name = self.file_name.value
        global _conf_file_destination
        _conf_file_destination = self.file_destination.value

    def on_cancel(self):
        self.parentApp.change_form('MAIN')

    def beforeEditing(self):
        self.vm_count.value = str(_vm_list_size)
        #self.windows_count.value = str(_vm_list_os_windows)
        #self.linux_count.value = str(_vm_list_os_linux)
        self.vm_list_box.set_values([str("VM: "+key+" OS: "+_vm_list[key].os_type) for key in _vm_list])



#first screen displayed - naming convention for screens Name_Form
class Main_Form(_nps.ActionFormV2):

    menu_options = ['New Config File', 'Add to Existing Config File [Not Implemented]']
    readme =['1. This application will generate well formed libvmi configuration files (libvmi.conf).',
             '2. Virtual Machine configurations are added to the application memory',
             'and will only be written to the actual file by choosing the "Write File" option',
             '3. Please reference libvmi.com/docs/gcode-install.html for config file info ']

    def create(self):
        self.menu_option    = self.add(_nps.TitleSelectOne, scroll_ext=True, max_height=3, name='Menu Options', values=self.menu_options )
        self.nextrely+=1
        self.tip1 = self.add(_nps.TitleFixedText, name="Tip:", value="Press CTRL + X to navigate using the menus on the next screen")
        self.nextrely+=1
        self.tip1 = self.add(_nps.TitleFixedText, name="Tip:", value="Press TAB to move between different options")
        self.nextrely+=1
        self.tip1 = self.add(_nps.TitleFixedText, name="Tip:", value="Press ENTER to select an option")
        self.nextrely+=1
        self.read = self.add(_nps.TitlePager, name ="Note:", values=self.readme)


    def on_ok(self):
        opt = self.menu_option.get_selected_objects()
        if not opt:
            error("Please select an option to continue or select 'Cancel' to exit the application ",ERROR_MSGS[0])
        elif opt[0] == self.menu_options[0]:
            self.parentApp.change_form('CONFIG')
        elif opt[0] == self.menu_options[1]:
            _nps.notify_confirm("This feature will be implemented in a future update", title="Invalid Option", form_color='STANDOUT', wrap=True, wide=False)
            pass


    def on_cancel(self):
        self.parentApp.change_form(None)


#app loader - start point
class Application(_nps.NPSAppManaged):
    def onStart(self):
        self.addForm('MAIN', Main_Form, name='LibVMI Config Editor '+_version)
        self.addForm('CONFIG', Config_Form, name='Libvmi Config File')
        self.addForm('NEW_LINUX', Add_Linux_Form, name='Add New Linux VM')
        self.addForm('NEW_WINDOWS', Add_Windows_Form, name='Add New Windows VM')
        self.addForm('LIST_VM', VM_List_Form, name='All Machines')
        self.addForm('WRITE_CONFIG',Write_Config_Form, name='Write Config To File')
        self.addForm('REMOVE_VM',Remove_VM_Form, name='Remove Virtual Machine')

        global _APP
        _APP = self

    def error_msg(self, message,msg_title):
        opt = _nps.notify_ok_cancel(message, title=msg_title, form_color='STANDOUT')
        #user wants to end
        if opt == True:
            _APP.setNextForm(None)
            _APP.editing = False
            _APP.switchFormNow()

    def change_form(self,name):
        self.switchForm(name)

if __name__ == '__main__':
    global _APP
    _APP = Application().run()
