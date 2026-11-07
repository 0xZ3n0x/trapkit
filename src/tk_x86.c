/*
 * tk_x86.c - the x86-64 facts a target's decoders are built on.
 *
 * A site has to be the exact encoding a trap handler can act on, so decoding
 * is verification, not guesswork.  These helpers cover the pieces every
 * target needs; the site-specific interpretation (which instruction, which
 * immediate pins the identity) lives with the patterns in the application.
 */
#include <asm/ptrace.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unaligned.h>

#include "tk.h"

/* Opcode of "mov r/m32, imm32" (C7 /0). */
#define TK_OPCODE_MOV_RM32_IMM32 0xC7

#define TK_MODRM_MOD_DISP8 1 /* mod field value meaning "8-bit displacement" */
#define TK_MODRM_RM_SIB 4    /* rm field value meaning "a SIB byte follows" */
#define TK_MODRM_REG_EXT 0   /* the /0 reg extension C7 uses */

/*
 * REX, operand/address size, lock, rep and segment override prefixes.
 *
 * The handler emulates a bare instruction, so any prefix immediately before
 * a site would change its meaning (a different operand size, a different
 * segment) and makes the match unusable.
 */
EXPORT_SYMBOL_GPL(tk_x86_is_prefix);

bool tk_x86_is_prefix(u8 byte)
{
    return (byte >= 0x40 && byte <= 0x4F) || /* REX */
           byte == 0x66 || byte == 0x67 ||   /* operand / address size */
           byte == 0xF0 ||                   /* lock */
           byte == 0xF2 || byte == 0xF3 ||   /* repne / rep */
           byte == 0x2E || byte == 0x36 || byte == 0x3E || byte == 0x26 || byte == 0x64 ||
           byte == 0x65; /* segment */
}

/*
 * mod=01 rm field -> byte offset of that base register inside struct pt_regs.
 * Only the register index is ever derived from game memory; the mapping onto
 * the kernel's own register layout stays in the framework.
 */
static const u8 tk_modrm_rm_to_pt_regs_offset[8] = {
    offsetof(struct pt_regs, ax), offsetof(struct pt_regs, cx), offsetof(struct pt_regs, dx),
    offsetof(struct pt_regs, bx), offsetof(struct pt_regs, sp), offsetof(struct pt_regs, bp),
    offsetof(struct pt_regs, si), offsetof(struct pt_regs, di),
};

EXPORT_SYMBOL_GPL(tk_x86_modrm_rm_to_regs);

u8 tk_x86_modrm_rm_to_regs(u8 rm)
{
    return tk_modrm_rm_to_pt_regs_offset[rm & 7];
}

EXPORT_SYMBOL_GPL(tk_x86_decode_mov_m32_imm32);

int tk_x86_decode_mov_m32_imm32(const u8* code, u8* base_reg, s8* disp, u32* imm)
{
    u8 modrm;

    if (code[0] != TK_OPCODE_MOV_RM32_IMM32)
    {
        return -EINVAL;
    }

    modrm = code[1];
    if ((modrm >> 6) != TK_MODRM_MOD_DISP8 || ((modrm >> 3) & 7) != TK_MODRM_REG_EXT ||
        (modrm & 7) == TK_MODRM_RM_SIB)
    {
        return -EINVAL;
    }

    *base_reg = tk_x86_modrm_rm_to_regs(modrm & 7);
    *disp = (s8)code[2];
    *imm = get_unaligned_le32(code + 3);
    return 0;
}
