// Profile for GNU Indent
// Specifies the C code formatting for LibVMI
//
// Author: Bryan D. Payne (bdpayne@acm.org)

// blank lines
--blank-lines-after-declarations
--blank-lines-after-procedures
--blank-lines-before-block-comments
--swallow-optional-blank-lines

// comments
--format-first-column-comments
--start-left-side-of-comments
--comment-indentation4
--declaration-comment-column4
--else-endif-column4

// statements
--braces-on-if-line
--dont-cuddle-else
--cuddle-do-while
--case-indentation0
--space-special-semicolon
--no-space-after-function-call-names
--space-after-cast

// declarations
--declaration-indentation1
--no-blank-lines-after-commas
--break-function-decl-args-end
--procnames-start-lines
--braces-on-struct-decl-line
--braces-after-func-def-line

// typedef declarations
-T pid_cache_entry_t
-T sym_cache_entry_t
-T v2p_cache_entry_t
-T kvm_instance_t
-T file_instance_t
-T driver_instance_t
-T libvmi_xenctrl_handle_t
-T libvmi_xenctrl_handle_t
-T xen_instance_t
-T memory_cache_entry_t
-T vmi_mode_t
-T status_t
-T os_t
-T win_ver_t
-T page_mode_t
-T reg_t
-T registers_t
-T addr_t
-T unicode_string_t
-T vmi_instance_t
-T DBGKD_DEBUG_DATA_HEADER64
-T KDDEBUGGER_DATA64
-T win32_unicode_string_t
-T win64_unicode_string_t
-T boyer_moore_data_t

// indentation
--indent-level4
--continuation-indentation4
--continue-at-parentheses
--tab-size4
--parameter-indentation4
--indent-label0

// breaking long lines
--line-length72
--break-after-boolean-operator
--ignore-newlines

// other
--no-tabs
