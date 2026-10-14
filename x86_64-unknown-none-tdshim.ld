/* td-shim (https://github.com/confidential-containers/td-shim) loads this
 * ELF as a relocatable "executable" payload: it copies the PT_LOAD segments
 * to wherever it has allocated the payload region, applies the
 * R_X86_64_RELATIVE relocations below, and jumps directly to `_start` in
 * 64-bit long mode with paging already enabled. There is no 16/32-bit
 * trampoline here (unlike x86_64-unknown-none.ld), and the image links at
 * base 0 so that td-shim's loader can rebase it with a simple add.
 */
ENTRY(_start)

SECTIONS
{
  . = 0;
  /* Unlike code_start/data_start/etc. below, this must be a proper
   * relocatable symbol (not an absolute constant like `ram_min = 0;`) so it
   * reflects the image's actual runtime load address after td-shim rebases
   * it -- otherwise the "PVH Header" memory descriptor built from
   * ram_min..code_start (see src/arch/x86_64/layout.rs) spans from GPA 0 to
   * code_start's *real* runtime address, bogusly covering all of low memory.
   */
  ram_min = .;
  .rodata : { *(.rodata .rodata.*) }
  . = ALIGN(4K);
  code_start = .;
  .text : { *(.text .text.*) }
  . = ALIGN(4K);
  code_end = .;

  data_start = .;
  .data : { *(.data .data.*) }
  .got : { *(.got .got.*) }

  /* The BSS section isn't mapped from file data. It is just zeroed in RAM. */
  .bss : {
    *(.bss .bss.*)
  }
  . = ALIGN(4K);
  data_end = .;

  /* Our stack grows down and is page-aligned. */
  stack_start = .;
  .stack (NOLOAD) : ALIGN(4K) { . += 128K; }
  stack_end = .;

  /* Strip symbols from the output binary (comment out to get symbols) */
  /DISCARD/ : {
    *(.symtab)
    *(.strtab)
  }
}
