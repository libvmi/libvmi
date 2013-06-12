// Profile for GNU Indent
// Specifies the C code formatting for LibVMI
//
// Author: Bryan D. Payne (bdpayne@acm.org)

// Base this on K&R, below we just have our deviations from this style
--k-and-r-style

// blank lines
--blank-lines-before-block-comments // bbb

// comments
--format-first-column-comments // fc1
--start-left-side-of-comments // sc
--comment-indentation4 // cn
--declaration-comment-column4 // cdn
--else-endif-column4 // cpn

// statements
--cuddle-do-while // cdw
--space-special-semicolon // ss

// declarations
--procnames-start-lines // psl
--braces-after-func-def-line // blf

// indentation
--parameter-indentation4 // ipn
--indent-label0 // iln

// breaking long lines
--line-length78 // ln
--break-after-boolean-operator // nbbo

// other
--no-tabs // nut

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

