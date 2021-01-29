#include "qemu/osdep.h"
#include "qemu-common.h"
#include "disas/bfd.h"
#include "elf.h"

#include "cpu.h"
#include "disas/disas.h"
#include "disas/capstone.h"

typedef struct CPUDebug {
    struct disassemble_info info;
    CPUState *cpu;
} CPUDebug;

#ifdef CONFIG_CAPSTONE
/* Temporary storage for the capstone library.  This will be alloced via
   malloc with a size private to the library; thus there's no reason not
   to share this across calls and across host vs target disassembly.  */
static __thread cs_insn *cap_insn;

/* Initialize the Capstone library.  */
/* ??? It would be nice to cache this.  We would need one handle for the
   host and one for the target.  For most targets we can reset specific
   parameters via cs_option(CS_OPT_MODE, new_mode), but we cannot change
   CS_ARCH_* in this way.  Thus we would need to be able to close and
   re-open the target handle with a different arch for the target in order
   to handle AArch64 vs AArch32 mode switching.  */
static cs_err cap_disas_start(disassemble_info *info, csh *handle)
{
    cs_mode cap_mode;
    cs_err err;

    cap_mode = (cs_mode)(info->cap_mode + (int)(info->endian == BFD_ENDIAN_BIG ? CS_MODE_BIG_ENDIAN
                 : CS_MODE_LITTLE_ENDIAN));

    err = cs_open((cs_arch)info->cap_arch, cap_mode, handle);
    if (err != CS_ERR_OK) {
        return err;
    }

    /* ??? There probably ought to be a better place to put this.  */
    if (info->cap_arch == CS_ARCH_X86) {
        /* We don't care about errors (if for some reason the library
           is compiled without AT&T syntax); the user will just have
           to deal with the Intel syntax.  */
        cs_option(*handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    }

    /* "Disassemble" unknown insns as ".byte W,X,Y,Z".  */
    cs_option(*handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    /* Allocate temp space for cs_disasm_iter.  */
    if (cap_insn == NULL) {
        cap_insn = cs_malloc(*handle);
        if (cap_insn == NULL) {
            cs_close(handle);
            return CS_ERR_MEM;
        }
    }
    return CS_ERR_OK;
}

# define cap_disas_target(i, p, s)  false
# define cap_disas_host(i, p, s)  false

#if !defined(CONFIG_USER_ONLY)
/* Disassemble COUNT insns at PC for the target.  */
static bool cap_disas_monitor(disassemble_info *info, uint64_t pc, int count)
{
    uint8_t cap_buf[32];
    csh handle;
    cs_insn *insn;
    size_t csize = 0;

    if (cap_disas_start(info, &handle) != CS_ERR_OK) {
        return false;
    }
    insn = cap_insn;

    while (1) {
        /* We want to read memory for one insn, but generically we do not
           know how much memory that is.  We have a small buffer which is
           known to be sufficient for all supported targets.  Try to not
           read beyond the page, Just In Case.  For even more simplicity,
           ignore the actual target page size and use a 1k boundary.  If
           that turns out to be insufficient, we'll come back around the
           loop and read more.  */
        uint64_t epc = QEMU_ALIGN_UP(pc + csize + 1, 1024);
        size_t tsize = MIN(sizeof(cap_buf) - csize, epc - pc);
        const uint8_t *cbuf = cap_buf;

        /* Make certain that we can make progress.  */
        assert(tsize != 0);
        info->read_memory_func(pc, cap_buf + csize, tsize, info);
        csize += tsize;

        if (cs_disasm_iter(handle, &cbuf, &csize, &pc, insn)) {
            (*info->fprintf_func)(info->stream,
                                  "0x%08" PRIx64 ":  %-12s %s\n",
                                  insn->address, insn->mnemonic,
                                  insn->op_str);
            if (--count <= 0) {
                break;
            }
        }
        memmove(cap_buf, cbuf, csize);
    }

    cs_close(&handle);
    return true;
}
#endif /* !CONFIG_USER_ONLY */
#else
# define cap_disas_target(i, p, s)  false
# define cap_disas_host(i, p, s)  false
# define cap_disas_monitor(i, p, c)  false
#endif /* CONFIG_CAPSTONE */
/* Get LENGTH bytes from info's buffer, at target address memaddr.
   Transfer them to myaddr.  */
static int
target_read_memory (bfd_vma memaddr,
                    bfd_byte *myaddr,
                    int length,
                    struct disassemble_info *info)
{
    CPUDebug* s = (CPUDebug*)(((uintptr_t)info) - offsetof(CPUDebug, info));
    /*CPUDebug *s = container_of(info, CPUDebug, info);*/

    cpu_memory_rw_debug(s->cpu, memaddr, myaddr, length, 0);
    return 0;
}
static void panda_disas(FILE* mon, CPUState* cpu, target_ulong pc, int nb_insn, int is_physical, int flags)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    int count, i;
    CPUDebug s;

    INIT_DISASSEMBLE_INFO(s.info, mon, fprintf);

    s.cpu = cpu;
    if (is_physical)
    {
        s.info.read_memory_func = target_read_memory;
    }
    else
    {
        s.info.read_memory_func = target_read_memory;
    }
    s.info.print_address_func = generic_print_address;
    s.info.buffer_vma = pc;
    s.info.cap_arch = -1;
    s.info.cap_mode = 0;

#ifdef TARGET_WORDS_BIGENDIAN
    s.info.endian = BFD_ENDIAN_BIG;
#else
    s.info.endian = BFD_ENDIAN_LITTLE;
#endif

    if (cc->disas_set_info) {
        cc->disas_set_info(cpu, &s.info);
    }

    if (s.info.cap_arch >= 0 && cap_disas_monitor(&s.info, pc, nb_insn)) {
        return;
    }

    if (!s.info.print_insn) {
        fprintf(mon, "0x" TARGET_FMT_lx
                       ": Asm output not supported on this arch\n", pc);
        return;
    }

    for(i = 0; i < nb_insn; i++) {
        fprintf(mon, "0x" TARGET_FMT_lx ":  ", pc);
        count = s.info.print_insn(pc, &s.info);
        fprintf(mon, "\n");
        if (count < 0)
            break;
        pc += count;
    }
}

static int cpu_disassembly_flags(CPUState* cpu)
{
    #ifdef TARGET_I386
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    #ifdef TARGET_X86_64
    if (env->hflags & HF_CS64_MASK)
        return 2;
    #endif
    return !!!(env->hflags & HF_CS32_MASK);
    #endif
    return 0;
}

void panda_uhaul_disas(FILE* out, CPUState* env, target_ulong pc, int nb_insn);
void panda_uhaul_disas(FILE* out, CPUState* env, target_ulong pc, int nb_insn)
{
    panda_disas(out, env, pc, nb_insn, 0, cpu_disassembly_flags(env));
}