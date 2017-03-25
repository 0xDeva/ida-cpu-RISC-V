from idaapi import *
import copy

def SIGNEXT(x, b):
    m = 1 << (b - 1)
    x = x & ((1 << b) - 1)
    return (x ^ m) - m


class DecodingError(Exception):
    pass

class openrisc_processor_t(processor_t):
    id = 0x8001 + 0x5571C
    flag = PR_SEGS | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE | PR_USE32 | PR_DEFSEG32
    cnbits = 8
    dnbits = 8
    author = "Deva"
    psnames = ["RISC-V"]
    plnames = ["RISC-V"]
    segreg_size = 0
    instruc_start = 0
    assembler = {
        "flag": ASH_HEXF0 | ASD_DECF0 | ASO_OCTF5 | ASB_BINF0 | AS_N2CHR,
        "uflag": 0,
        "name": "OpenRISC asm",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": ".ascii",
        "a_byte": ".byte",
        "a_word": ".word",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": "PC",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
    }

    reg_names = regNames = [
        "zero", "ra", "sp", "s3", "s4",
        "t0", "t1", "t2", "s0",
        "s1", "a0", "a1", "a2", "a3",
        "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5",
        "s6", "s7", "s8", "t0", "t1",
        "t2", "t3", "t4", "t5", "t6",
        #virutal 
        "CS", "DS"
    ]

    instruc = instrs = [{'name': 'lui', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lui rd,imm'},
{'name': 'auipc', 'feature': CF_USE1 | CF_USE2, 'cmt': 'auipc rd,offset'},
{'name': 'jal', 'feature': CF_USE1 | CF_USE2 | CF_CALL, 'cmt': 'jal rd,offset'},
{'name': 'jalr', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CALL, 'cmt': 'jalr rd,rs1,offset'},
{'name': 'beq', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'beq rs1,rs2,offset'},
{'name': 'bne', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'bne rs1,rs2,offset'},
{'name': 'blt', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'blt rs1,rs2,offset'},
{'name': 'bge', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'bge rs1,rs2,offset'},
{'name': 'bltu', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'bltu rs1,rs2,offset'},
{'name': 'bgeu', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'bgeu rs1,rs2,offset'},
{'name': 'lb', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lb rd,offset(rs1)'},
{'name': 'lh', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lh rd,offset(rs1)'},
{'name': 'lw', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lw rd,offset(rs1)'},
{'name': 'lbu', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lbu rd,offset(rs1)'},
{'name': 'lhu', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lhu rd,offset(rs1)'},
{'name': 'sb', 'feature': CF_USE1 | CF_USE2, 'cmt': 'sb rs2,offset(rs1)'},
{'name': 'sh', 'feature': CF_USE1 | CF_USE2, 'cmt': 'sh rs2,offset(rs1)'},
{'name': 'sw', 'feature': CF_USE1 | CF_USE2, 'cmt': 'sw rs2,offset(rs1)'},
{'name': 'addi', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'addi rd,rs1,imm'},
{'name': 'slti', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'slti rd,rs1,imm'},
{'name': 'sltiu', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'sltiu rd,rs1,imm'},
{'name': 'xori', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'xori rd,rs1,imm'},
{'name': 'ori', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'ori rd,rs1,imm'},
{'name': 'andi', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'andi rd,rs1,imm'},
{'name': 'slli', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'slli rd,rs1,imm'},
{'name': 'srli', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'srli rd,rs1,imm'},
{'name': 'srai', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'srai rd,rs1,imm'},
{'name': 'add', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'add rd,rs1,rs2'},
{'name': 'sub', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'sub rd,rs1,rs2'},
{'name': 'sll', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'sll rd,rs1,rs2'},
{'name': 'slt', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'slt rd,rs1,rs2'},
{'name': 'sltu', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'sltu rd,rs1,rs2'},
{'name': 'xor', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'xor rd,rs1,rs2'},
{'name': 'srl', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'srl rd,rs1,rs2'},
{'name': 'sra', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'sra rd,rs1,rs2'},
{'name': 'or', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'or rd,rs1,rs2'},
{'name': 'and', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'and rd,rs1,rs2'},
{'name': 'lwu', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lwu rd,offset(rs1)'},
{'name': 'ld', 'feature': CF_USE1 | CF_USE2, 'cmt': 'ld rd,offset(rs1)'},
{'name': 'sd', 'feature': CF_USE1 | CF_USE2, 'cmt': 'sd rs2,offset(rs1)'},
{'name': 'addiw', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'addiw rd,rs1,imm'},
{'name': 'slliw', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'slliw rd,rs1,imm'},
{'name': 'srliw', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'srliw rd,rs1,imm'},
{'name': 'sraiw', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'sraiw rd,rs1,imm'},
{'name': 'addw', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'addw rd,rs1,rs2'},
{'name': 'subw', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'subw rd,rs1,rs2'},
{'name': 'sllw', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'sllw rd,rs1,rs2'},
{'name': 'srlw', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'srlw rd,rs1,rs2'},
{'name': 'sraw', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'sraw rd,rs1,rs2'},
{'name': 'ldu', 'feature': CF_USE1 | CF_USE2, 'cmt': 'ldu rd,offset(rs1)'},
{'name': 'lq', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lq rd,offset(rs1)'},
{'name': 'sq', 'feature': CF_USE1 | CF_USE2, 'cmt': 'sq rs2,offset(rs1)'},
{'name': 'addid', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'addid rd,rs1,imm'},
{'name': 'sllid', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'sllid rd,rs1,imm'},
{'name': 'srlid', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'srlid rd,rs1,imm'},
{'name': 'sraid', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'sraid rd,rs1,imm'},
{'name': 'addd', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'addd rd,rs1,rs2'},
{'name': 'subd', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'subd rd,rs1,rs2'},
{'name': 'slld', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'slld rd,rs1,rs2'},
{'name': 'srld', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'srld rd,rs1,rs2'},
{'name': 'srad', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'srad rd,rs1,rs2'},
{'name': 'mul', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'mul rd,rs1,rs2'},
{'name': 'mulh', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'mulh rd,rs1,rs2'},
{'name': 'mulhsu', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'mulhsu rd,rs1,rs2'},
{'name': 'mulhu', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'mulhu rd,rs1,rs2'},
{'name': 'div', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'div rd,rs1,rs2'},
{'name': 'divu', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'divu rd,rs1,rs2'},
{'name': 'rem', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'rem rd,rs1,rs2'},
{'name': 'remu', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'remu rd,rs1,rs2'},
{'name': 'mulw', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'mulw rd,rs1,rs2'},
{'name': 'divw', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'divw rd,rs1,rs2'},
{'name': 'divuw', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'divuw rd,rs1,rs2'},
{'name': 'remw', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'remw rd,rs1,rs2'},
{'name': 'remuw', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'remuw rd,rs1,rs2'},
{'name': 'muld', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'muld rd,rs1,rs2'},
{'name': 'divd', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'divd rd,rs1,rs2'},
{'name': 'divud', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'divud rd,rs1,rs2'},
{'name': 'remd', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'remd rd,rs1,rs2'},
{'name': 'remud', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'remud rd,rs1,rs2'},
{'name': 'lr.w', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lr.w aqrl,rd,(rs1)'},
{'name': 'sc.w', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'sc.w aqrl,rd,rs2,(rs1)'},
{'name': 'amoswap.w', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amoswap.w aqrl,rd,rs2,(rs1)'},
{'name': 'amoadd.w', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amoadd.w aqrl,rd,rs2,(rs1)'},
{'name': 'amoxor.w', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amoxor.w aqrl,rd,rs2,(rs1)'},
{'name': 'amoor.w', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amoor.w aqrl,rd,rs2,(rs1)'},
{'name': 'amoand.w', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amoand.w aqrl,rd,rs2,(rs1)'},
{'name': 'amomin.w', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amomin.w aqrl,rd,rs2,(rs1)'},
{'name': 'amomax.w', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amomax.w aqrl,rd,rs2,(rs1)'},
{'name': 'amominu.w', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amominu.w aqrl,rd,rs2,(rs1)'},
{'name': 'amomaxu.w', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amomaxu.w aqrl,rd,rs2,(rs1)'},
{'name': 'lr.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lr.d aqrl,rd,(rs1)'},
{'name': 'sc.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'sc.d aqrl,rd,rs2,(rs1)'},
{'name': 'amoswap.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amoswap.d aqrl,rd,rs2,(rs1)'},
{'name': 'amoadd.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amoadd.d aqrl,rd,rs2,(rs1)'},
{'name': 'amoxor.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amoxor.d aqrl,rd,rs2,(rs1)'},
{'name': 'amoor.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amoor.d aqrl,rd,rs2,(rs1)'},
{'name': 'amoand.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amoand.d aqrl,rd,rs2,(rs1)'},
{'name': 'amomin.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amomin.d aqrl,rd,rs2,(rs1)'},
{'name': 'amomax.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amomax.d aqrl,rd,rs2,(rs1)'},
{'name': 'amominu.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amominu.d aqrl,rd,rs2,(rs1)'},
{'name': 'amomaxu.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amomaxu.d aqrl,rd,rs2,(rs1)'},
{'name': 'lr.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lr.q aqrl,rd,(rs1)'},
{'name': 'sc.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'sc.q aqrl,rd,rs2,(rs1)'},
{'name': 'amoswap.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amoswap.q aqrl,rd,rs2,(rs1)'},
{'name': 'amoadd.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amoadd.q aqrl,rd,rs2,(rs1)'},
{'name': 'amoxor.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amoxor.q aqrl,rd,rs2,(rs1)'},
{'name': 'amoor.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amoor.q aqrl,rd,rs2,(rs1)'},
{'name': 'amoand.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amoand.q aqrl,rd,rs2,(rs1)'},
{'name': 'amomin.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amomin.q aqrl,rd,rs2,(rs1)'},
{'name': 'amomax.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amomax.q aqrl,rd,rs2,(rs1)'},
{'name': 'amominu.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amominu.q aqrl,rd,rs2,(rs1)'},
{'name': 'amomaxu.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'amomaxu.q aqrl,rd,rs2,(rs1)'},
{'name': 'ecall', 'feature': 0, 'cmt': 'ecall none'},
{'name': 'ebreak', 'feature': 0, 'cmt': 'ebreak none'},
{'name': 'uret', 'feature': 0, 'cmt': 'uret none'},
{'name': 'sret', 'feature': 0, 'cmt': 'sret none'},
{'name': 'hret', 'feature': 0, 'cmt': 'hret none'},
{'name': 'mret', 'feature': 0, 'cmt': 'mret none'},
{'name': 'dret', 'feature': 0, 'cmt': 'dret none'},
{'name': 'sfence.vm', 'feature': CF_USE1, 'cmt': 'sfence.vm rs1'},
{'name': 'wfi', 'feature': 0, 'cmt': 'wfi none'},
{'name': 'csrrw', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'csrrw rd,csr,rs1'},
{'name': 'csrrs', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'csrrs rd,csr,rs1'},
{'name': 'csrrc', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'csrrc rd,csr,rs1'},
{'name': 'csrrwi', 'feature': CF_USE1 | CF_USE2, 'cmt': 'csrrwi rd,csr,zimm'},
{'name': 'csrrsi', 'feature': CF_USE1 | CF_USE2, 'cmt': 'csrrsi rd,csr,zimm'},
{'name': 'csrrci', 'feature': CF_USE1 | CF_USE2, 'cmt': 'csrrci rd,csr,zimm'},
{'name': 'flw', 'feature': CF_USE1 | CF_USE2, 'cmt': 'flw frd,offset(rs1)'},
{'name': 'fsw', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fsw frs2,offset(rs1)'},
{'name': 'fmadd.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'fmadd.s rm,frd,frs1,frs2,frs3'},
{'name': 'fmsub.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'fmsub.s rm,frd,frs1,frs2,frs3'},
{'name': 'fnmsub.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'fnmsub.s rm,frd,frs1,frs2,frs3'},
{'name': 'fnmadd.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'fnmadd.s rm,frd,frs1,frs2,frs3'},
{'name': 'fadd.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fadd.s rm,frd,frs1,frs2'},
{'name': 'fsub.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fsub.s rm,frd,frs1,frs2'},
{'name': 'fmul.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fmul.s rm,frd,frs1,frs2'},
{'name': 'fdiv.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fdiv.s rm,frd,frs1,frs2'},
{'name': 'fsgnj.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fsgnj.s frd,frs1,frs2'},
{'name': 'fsgnjn.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fsgnjn.s frd,frs1,frs2'},
{'name': 'fsgnjx.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fsgnjx.s frd,frs1,frs2'},
{'name': 'fmin.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fmin.s frd,frs1,frs2'},
{'name': 'fmax.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fmax.s frd,frs1,frs2'},
{'name': 'fsqrt.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fsqrt.s rm,frd,frs1'},
{'name': 'fle.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fle.s rd,frs1,frs2'},
{'name': 'flt.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'flt.s rd,frs1,frs2'},
{'name': 'feq.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'feq.s rd,frs1,frs2'},
{'name': 'fcvt.w.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.w.s rm,rd,frs1'},
{'name': 'fcvt.wu.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.wu.s rm,rd,frs1'},
{'name': 'fcvt.s.w', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.s.w rm,frd,rs1'},
{'name': 'fcvt.s.wu', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.s.wu rm,frd,rs1'},
{'name': 'fmv.x.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fmv.x.s rd,frs1'},
{'name': 'fclass.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fclass.s rd,frs1'},
{'name': 'fmv.s.x', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fmv.s.x frd,rs1'},
{'name': 'fcvt.l.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.l.s rm,rd,frs1'},
{'name': 'fcvt.lu.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.lu.s rm,rd,frs1'},
{'name': 'fcvt.s.l', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.s.l rm,frd,rs1'},
{'name': 'fcvt.s.lu', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.s.lu rm,frd,rs1'},
{'name': 'fld', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fld frd,offset(rs1)'},
{'name': 'fsd', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fsd frs2,offset(rs1)'},
{'name': 'fmadd.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'fmadd.d rm,frd,frs1,frs2,frs3'},
{'name': 'fmsub.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'fmsub.d rm,frd,frs1,frs2,frs3'},
{'name': 'fnmsub.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'fnmsub.d rm,frd,frs1,frs2,frs3'},
{'name': 'fnmadd.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'fnmadd.d rm,frd,frs1,frs2,frs3'},
{'name': 'fadd.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fadd.d rm,frd,frs1,frs2'},
{'name': 'fsub.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fsub.d rm,frd,frs1,frs2'},
{'name': 'fmul.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fmul.d rm,frd,frs1,frs2'},
{'name': 'fdiv.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fdiv.d rm,frd,frs1,frs2'},
{'name': 'fsgnj.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fsgnj.d frd,frs1,frs2'},
{'name': 'fsgnjn.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fsgnjn.d frd,frs1,frs2'},
{'name': 'fsgnjx.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fsgnjx.d frd,frs1,frs2'},
{'name': 'fmin.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fmin.d frd,frs1,frs2'},
{'name': 'fmax.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fmax.d frd,frs1,frs2'},
{'name': 'fcvt.s.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.s.d rm,frd,frs1'},
{'name': 'fcvt.d.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.d.s rm,frd,frs1'},
{'name': 'fsqrt.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fsqrt.d rm,frd,frs1'},
{'name': 'fle.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fle.d rd,frs1,frs2'},
{'name': 'flt.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'flt.d rd,frs1,frs2'},
{'name': 'feq.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'feq.d rd,frs1,frs2'},
{'name': 'fcvt.w.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.w.d rm,rd,frs1'},
{'name': 'fcvt.wu.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.wu.d rm,rd,frs1'},
{'name': 'fcvt.d.w', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.d.w rm,frd,rs1'},
{'name': 'fcvt.d.wu', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.d.wu rm,frd,rs1'},
{'name': 'fclass.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fclass.d rd,frs1'},
{'name': 'fcvt.l.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.l.d rm,rd,frs1'},
{'name': 'fcvt.lu.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.lu.d rm,rd,frs1'},
{'name': 'fmv.x.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fmv.x.d rd,frs1'},
{'name': 'fcvt.d.l', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.d.l rm,frd,rs1'},
{'name': 'fcvt.d.lu', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.d.lu rm,frd,rs1'},
{'name': 'fmv.d.x', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fmv.d.x frd,rs1'},
{'name': 'flq', 'feature': CF_USE1 | CF_USE2, 'cmt': 'flq frd,offset(rs1)'},
{'name': 'fsq', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fsq frs2,offset(rs1)'},
{'name': 'fmadd.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'fmadd.q rm,frd,frs1,frs2,frs3'},
{'name': 'fmsub.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'fmsub.q rm,frd,frs1,frs2,frs3'},
{'name': 'fnmsub.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'fnmsub.q rm,frd,frs1,frs2,frs3'},
{'name': 'fnmadd.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'fnmadd.q rm,frd,frs1,frs2,frs3'},
{'name': 'fadd.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fadd.q rm,frd,frs1,frs2'},
{'name': 'fsub.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fsub.q rm,frd,frs1,frs2'},
{'name': 'fmul.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fmul.q rm,frd,frs1,frs2'},
{'name': 'fdiv.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fdiv.q rm,frd,frs1,frs2'},
{'name': 'fsgnj.q', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fsgnj.q frd,frs1,frs2'},
{'name': 'fsgnjn.q', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fsgnjn.q frd,frs1,frs2'},
{'name': 'fsgnjx.q', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fsgnjx.q frd,frs1,frs2'},
{'name': 'fmin.q', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fmin.q frd,frs1,frs2'},
{'name': 'fmax.q', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fmax.q frd,frs1,frs2'},
{'name': 'fcvt.s.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.s.q rm,frd,frs1'},
{'name': 'fcvt.q.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.q.s rm,frd,frs1'},
{'name': 'fcvt.d.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.d.q rm,frd,frs1'},
{'name': 'fcvt.q.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.q.d rm,frd,frs1'},
{'name': 'fsqrt.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fsqrt.q rm,frd,frs1'},
{'name': 'fle.q', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fle.q rd,frs1,frs2'},
{'name': 'flt.q', 'feature': CF_USE1 | CF_USE2, 'cmt': 'flt.q rd,frs1,frs2'},
{'name': 'feq.q', 'feature': CF_USE1 | CF_USE2, 'cmt': 'feq.q rd,frs1,frs2'},
{'name': 'fcvt.w.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.w.q rm,rd,frs1'},
{'name': 'fcvt.wu.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.wu.q rm,rd,frs1'},
{'name': 'fcvt.q.w', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.q.w rm,frd,rs1'},
{'name': 'fcvt.q.wu', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.q.wu rm,frd,rs1'},
{'name': 'fclass.q', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fclass.q rd,frs1'},
{'name': 'fcvt.l.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.l.q rm,rd,frs1'},
{'name': 'fcvt.lu.q', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.lu.q rm,rd,frs1'},
{'name': 'fcvt.q.l', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.q.l rm,frd,rs1'},
{'name': 'fcvt.q.lu', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'fcvt.q.lu rm,frd,rs1'},
{'name': 'fmv.x.q', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fmv.x.q rd,frs1'},
{'name': 'fmv.q.x', 'feature': CF_USE1 | CF_USE2, 'cmt': 'fmv.q.x frd,rs1'}]


    instruc_end = len(instruc)

    def __init__(self):
        processor_t.__init__(self)
        self._init_instructions()
        self._init_registers()
        self.delayed_jmp = dict()
        self.last_is_lui = None

    def _init_instructions(self):
        self.inames = {}
        for idx, ins in enumerate(self.instrs):
            self.inames[ins['name']] = idx

    def _init_registers(self):
        self.reg_ids = {}
        for i, reg in enumerate(self.reg_names):
            self.reg_ids[reg] = i
        self.regFirstSreg = self.regCodeSreg = self.reg_ids["CS"]
        self.regLastSreg = self.regDataSreg = self.reg_ids["DS"]

    def _read_cmd_dword(self):
        ea = self.cmd.ea + self.cmd.size
        dword = get_full_long(ea)
        self.cmd.size += 4
        return dword


    def _ana(self):
        cmd = self.cmd
        opcode = self._read_cmd_dword()
        op_m7_sl25_sr20 = ((opcode & 0xfe000000) >> 20)
        op_m3_sl22_sr22 = ((opcode & 0x1c00000) >> 22)
        op_m1_sl20_sr20 = ((opcode & 0x100000) >> 20)
        op_m8_sl22_sr22 = ((opcode & 0x3fc00000) >> 22)
        op_m1_sl12_sr12 = ((opcode & 0x1000) >> 12)
        op_m5_sl15_sr15 = ((opcode & 0xf8000) >> 15)
        op_m14_sl7_sr7 = ((opcode & 0x1fff80) >> 7)
        op_m1_sl22_sr22 = ((opcode & 0x400000) >> 22)
        op_m20_sl12_sr12 = ((opcode & 0xfffff000) >> 12)
        op_m2_sl4_sr4 = ((opcode & 0x30) >> 4)
        op_m4_sl26_sr26 = ((opcode & 0x3c000000) >> 26)
        op_m1_sl21_sr21 = ((opcode & 0x200000) >> 21)
        op_m4_sl3_sr3 = ((opcode & 0x78) >> 3)
        op_m8_sl7_sr7 = ((opcode & 0x7f80) >> 7)
        op_m7_sl25_sr25 = ((opcode & 0xfe000000) >> 25)
        op_m2_sl30_sr30 = ((opcode & 0xc0000000) >> 30)
        op_m5_sl7_sr7 = ((opcode & 0xf80) >> 7)
        op_m2_sl13_sr13 = ((opcode & 0x6000) >> 13)
        op_m5_sl2_sr2 = ((opcode & 0x7c) >> 2)
        op_m1_sl5_sr5 = ((opcode & 0x20) >> 5)
        op_m1_sl28_sr28 = ((opcode & 0x10000000) >> 28)
        op_m3_sl27_sr27 = ((opcode & 0x38000000) >> 27)
        op_m10_sl22_sr22 = ((opcode & 0xffc00000) >> 22)
        op_m1_sl30_sr30 = ((opcode & 0x40000000) >> 30)
        op_m7_sl22_sr22 = ((opcode & 0x1fc00000) >> 22)
        op_m4_sl0_sr0 = ((opcode & 0xf) >> 0)
        op_m2_sl22_sr22 = ((opcode & 0xc00000) >> 22)
        op_m2_sl3_sr3 = ((opcode & 0x18) >> 3)
        op_m1_sl29_sr29 = ((opcode & 0x20000000) >> 29)
        op_m3_sl0_sr0 = ((opcode & 0x7) >> 0)
        op_m5_sl25_sr25 = ((opcode & 0x3e000000) >> 25)
        op_m1_sl26_sr26 = ((opcode & 0x4000000) >> 26)
        op_m1_sl4_sr4 = ((opcode & 0x10) >> 4)
        op_m3_sl2_sr2 = ((opcode & 0x1c) >> 2)
        op_m9_sl21_sr21 = ((opcode & 0x3fe00000) >> 21)
        op_m2_sl28_sr28 = ((opcode & 0x30000000) >> 28)
        op_m2_sl26_sr26 = ((opcode & 0xc000000) >> 26)
        op_m1_sl31_sr31 = ((opcode & 0x80000000) >> 31)
        op_m1_sl25_sr25 = ((opcode & 0x2000000) >> 25)
        op_m3_sl25_sr25 = ((opcode & 0xe000000) >> 25)
        op_m2_sl29_sr29 = ((opcode & 0x60000000) >> 29)
        op_m2_sl20_sr20 = ((opcode & 0x300000) >> 20)
        op_m2_sl0_sr0 = ((opcode & 0x3) >> 0)
        op_m25_sl7_sr7 = ((opcode & 0xffffff80) >> 7)
        op_m3_sl3_sr3 = ((opcode & 0x38) >> 3)
        op_m7_sl20_sr20 = ((opcode & 0x7f00000) >> 20)
        op_m12_sl20_sr20 = ((opcode & 0xfff00000) >> 20)
        op_m1_sl6_sr6 = ((opcode & 0x40) >> 6)
        op_m9_sl20_sr20 = ((opcode & 0x1ff00000) >> 20)
        op_m10_sl20_sr20 = ((opcode & 0x3ff00000) >> 20)
        op_m13_sl7_sr7 = ((opcode & 0xfff80) >> 7)
        op_m3_sl4_sr4 = ((opcode & 0x70) >> 4)
        op_m5_sl27_sr27 = ((opcode & 0xf8000000) >> 27)
        op_m1_sl14_sr14 = ((opcode & 0x4000) >> 14)
        op_m4_sl25_sr25 = ((opcode & 0x1e000000) >> 25)
        op_m1_sl2_sr2 = ((opcode & 0x4) >> 2)
        op_m4_sl21_sr21 = ((opcode & 0x1e00000) >> 21)
        op_m1_sl13_sr13 = ((opcode & 0x2000) >> 13)
        op_m3_sl26_sr26 = ((opcode & 0x1c000000) >> 26)
        op_m5_sl20_sr20 = ((opcode & 0x1f00000) >> 20)
        op_m5_sl23_sr23 = ((opcode & 0xf800000) >> 23)
        op_m4_sl28_sr28 = ((opcode & 0xf0000000) >> 28)
        op_m7_sl21_sr21 = ((opcode & 0xfe00000) >> 21)
        op_m2_sl2_sr2 = ((opcode & 0xc) >> 2)
        op_m8_sl20_sr20 = ((opcode & 0xff00000) >> 20)
        op_m6_sl26_sr26 = ((opcode & 0xfc000000) >> 26)
        op_m17_sl15_sr15 = ((opcode & 0xffff8000) >> 15)
        op_m6_sl20_sr20 = ((opcode & 0x3f00000) >> 20)
        op_m2_sl5_sr5 = ((opcode & 0x60) >> 5)
        op_m6_sl22_sr22 = ((opcode & 0xfc00000) >> 22)
        op_m1_sl27_sr27 = ((opcode & 0x8000000) >> 27)
        op_m2_sl12_sr12 = ((opcode & 0x3000) >> 12)
        op_m4_sl2_sr2 = ((opcode & 0x3c) >> 2)
        op_m2_sl24_sr24 = ((opcode & 0x3000000) >> 24)
        op_m3_sl12_sr12 = ((opcode & 0x7000) >> 12)
        op_m2_sl25_sr25 = ((opcode & 0x6000000) >> 25)
        op_m2_sl27_sr27 = ((opcode & 0x18000000) >> 27)
        op_m11_sl21_sr21 = ((opcode & 0xffe00000) >> 21)
        op_m3_sl29_sr29 = ((opcode & 0xe0000000) >> 29)
        op_m1_sl3_sr3 = ((opcode & 0x8) >> 3)
        op_m4_sl27_sr27 = ((opcode & 0x78000000) >> 27)
        
        if (op_m3_sl0_sr0 == 0x7) and (op_m1_sl3_sr3 == 0x0) and (op_m2_sl4_sr4 == 0x3) and (op_m1_sl6_sr6 == 0x0):
            cmd.itype = self.inames['lui']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_imm
            cmd[1].value = SIGNEXT(op_m20_sl12_sr12, 20)
            cmd[1].dtyp = dt_word
        elif (op_m3_sl0_sr0 == 0x7) and (op_m1_sl3_sr3 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m2_sl5_sr5 == 0x0):
            cmd.itype = self.inames['auipc']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_near
            cmd[1].addr = cmd.ea + SIGNEXT(op_m20_sl12_sr12, 20)
            cmd[1].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m2_sl5_sr5 == 0x3):
            cmd.itype = self.inames['jal']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_near
            cmd[1].addr = cmd.ea + SIGNEXT(op_m12_sl20_sr20-1, 12)
            cmd[1].dtyp = dt_word
        elif (op_m3_sl0_sr0 == 0x7) and (op_m2_sl3_sr3 == 0x0) and (op_m2_sl5_sr5 == 0x3) and (op_m3_sl12_sr12 == 0x0):
            cmd.itype = self.inames['jalr']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_near
            cmd[2].addr = cmd.ea + SIGNEXT(op_m12_sl20_sr20-1, 12)
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m3_sl2_sr2 == 0x0) and (op_m2_sl5_sr5 == 0x3) and (op_m3_sl12_sr12 == 0x0):
            cmd.itype = self.inames['beq']
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT((op_m5_sl7_sr7 | op_m7_sl25_sr20), 12)
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m3_sl2_sr2 == 0x0) and (op_m2_sl5_sr5 == 0x3) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0):
            cmd.itype = self.inames['bne']
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT((op_m5_sl7_sr7 | op_m7_sl25_sr20), 12)
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m3_sl2_sr2 == 0x0) and (op_m2_sl5_sr5 == 0x3) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1):
            cmd.itype = self.inames['blt']
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT((op_m5_sl7_sr7 | op_m7_sl25_sr20), 12)
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m3_sl2_sr2 == 0x0) and (op_m2_sl5_sr5 == 0x3) and (op_m1_sl12_sr12 == 0x1) and (op_m1_sl13_sr13 == 0x0) and (op_m1_sl14_sr14 == 0x1):
            cmd.itype = self.inames['bge']
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT((op_m5_sl7_sr7 | op_m7_sl25_sr20), 12)
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m3_sl2_sr2 == 0x0) and (op_m2_sl5_sr5 == 0x3) and (op_m1_sl12_sr12 == 0x0) and (op_m2_sl13_sr13 == 0x3):
            cmd.itype = self.inames['bltu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl15_sr15
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl20_sr20
            cmd[1].dtyp = dt_word
            cmd[2].type = o_near
            cmd[2].addr = cmd.ea + SIGNEXT((op_m5_sl7_sr7 | op_m7_sl25_sr20), 12)
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m3_sl2_sr2 == 0x0) and (op_m2_sl5_sr5 == 0x3) and (op_m3_sl12_sr12 == 0x7):
            cmd.itype = self.inames['bgeu']
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT((op_m5_sl7_sr7 | op_m7_sl25_sr20), 12)
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m5_sl2_sr2 == 0x0) and (op_m3_sl12_sr12 == 0x0):
            cmd.itype = self.inames['lb']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = op_m12_sl20_sr20
            cmd[1].reg = op_m5_sl15_sr15
        elif (op_m2_sl0_sr0 == 0x3) and (op_m5_sl2_sr2 == 0x0) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0):
            cmd.itype = self.inames['lh']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = op_m12_sl20_sr20
            cmd[1].reg = op_m5_sl15_sr15
        elif (op_m2_sl0_sr0 == 0x3) and (op_m5_sl2_sr2 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0):
            cmd.itype = self.inames['lw']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = op_m12_sl20_sr20
            cmd[1].reg = op_m5_sl15_sr15
        elif (op_m2_sl0_sr0 == 0x3) and (op_m5_sl2_sr2 == 0x0) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1):
            cmd.itype = self.inames['lbu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = op_m12_sl20_sr20
            cmd[1].reg = op_m5_sl15_sr15
        elif (op_m2_sl0_sr0 == 0x3) and (op_m5_sl2_sr2 == 0x0) and (op_m1_sl12_sr12 == 0x1) and (op_m1_sl13_sr13 == 0x0) and (op_m1_sl14_sr14 == 0x1):
            cmd.itype = self.inames['lhu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = op_m12_sl20_sr20
            cmd[1].reg = op_m5_sl15_sr15
        elif (op_m2_sl0_sr0 == 0x3) and (op_m3_sl2_sr2 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m3_sl12_sr12 == 0x0):
            cmd.itype = self.inames['sb']
            cmd[0].type = o_displ
            cmd[0].addr = (op_m5_sl7_sr7 | op_m7_sl25_sr20)
            cmd[0].reg = op_m5_sl15_sr15
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl20_sr20
            cmd[1].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m3_sl2_sr2 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0):
            cmd.itype = self.inames['sh']
            cmd[0].type = o_displ
            cmd[0].addr = (op_m5_sl7_sr7 | op_m7_sl25_sr20)
            cmd[0].reg = op_m5_sl15_sr15
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl20_sr20
            cmd[1].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m3_sl2_sr2 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0):
            cmd.itype = self.inames['sw']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl20_sr20
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = (op_m5_sl7_sr7 | op_m7_sl25_sr20)
            cmd[1].reg = op_m5_sl15_sr15
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m2_sl5_sr5 == 0x0) and (op_m3_sl12_sr12 == 0x0):
            cmd.itype = self.inames['addi']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = SIGNEXT(op_m12_sl20_sr20, 12)
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m2_sl5_sr5 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0):
            cmd.itype = self.inames['slti']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = SIGNEXT(op_m12_sl20_sr20, 12)
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m2_sl5_sr5 == 0x0) and (op_m2_sl12_sr12 == 0x3) and (op_m1_sl14_sr14 == 0x0):
            cmd.itype = self.inames['sltiu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = SIGNEXT(op_m12_sl20_sr20, 12)
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m2_sl5_sr5 == 0x0) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1):
            cmd.itype = self.inames['xori']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = SIGNEXT(op_m12_sl20_sr20, 12)
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m2_sl5_sr5 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m2_sl13_sr13 == 0x3):
            cmd.itype = self.inames['ori']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = SIGNEXT(op_m12_sl20_sr20, 12)
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m2_sl5_sr5 == 0x0) and (op_m3_sl12_sr12 == 0x7):
            cmd.itype = self.inames['andi']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = SIGNEXT(op_m12_sl20_sr20, 12)
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m2_sl5_sr5 == 0x0) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0) and (op_m5_sl27_sr27 == 0x0):
            cmd.itype = self.inames['slli']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = op_m7_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m2_sl5_sr5 == 0x0) and (op_m1_sl12_sr12 == 0x1) and (op_m1_sl13_sr13 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m5_sl27_sr27 == 0x0):
            cmd.itype = self.inames['srli']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = op_m7_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m2_sl5_sr5 == 0x0) and (op_m1_sl12_sr12 == 0x1) and (op_m1_sl13_sr13 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m3_sl27_sr27 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['srai']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = op_m7_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m2_sl4_sr4 == 0x3) and (op_m1_sl6_sr6 == 0x0) and (op_m3_sl12_sr12 == 0x0) and (op_m7_sl25_sr25 == 0x0):
            cmd.itype = self.inames['add']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m2_sl4_sr4 == 0x3) and (op_m1_sl6_sr6 == 0x0) and (op_m3_sl12_sr12 == 0x0) and (op_m5_sl25_sr25 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['sub']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m2_sl4_sr4 == 0x3) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0) and (op_m7_sl25_sr25 == 0x0):
            cmd.itype = self.inames['sll']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m2_sl4_sr4 == 0x3) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0) and (op_m7_sl25_sr25 == 0x0):
            cmd.itype = self.inames['slt']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m2_sl4_sr4 == 0x3) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x3) and (op_m1_sl14_sr14 == 0x0) and (op_m7_sl25_sr25 == 0x0):
            cmd.itype = self.inames['sltu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m2_sl4_sr4 == 0x3) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m7_sl25_sr25 == 0x0):
            cmd.itype = self.inames['xor']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m2_sl4_sr4 == 0x3) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x1) and (op_m1_sl13_sr13 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m7_sl25_sr25 == 0x0):
            cmd.itype = self.inames['srl']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m2_sl4_sr4 == 0x3) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x1) and (op_m1_sl13_sr13 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m5_sl25_sr25 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['sra']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m2_sl4_sr4 == 0x3) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m2_sl13_sr13 == 0x3) and (op_m7_sl25_sr25 == 0x0):
            cmd.itype = self.inames['or']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m2_sl4_sr4 == 0x3) and (op_m1_sl6_sr6 == 0x0) and (op_m3_sl12_sr12 == 0x7) and (op_m7_sl25_sr25 == 0x0):
            cmd.itype = self.inames['and']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m5_sl2_sr2 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m2_sl13_sr13 == 0x3):
            cmd.itype = self.inames['lwu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = op_m12_sl20_sr20
            cmd[1].reg = op_m5_sl15_sr15
        elif (op_m2_sl0_sr0 == 0x3) and (op_m5_sl2_sr2 == 0x0) and (op_m2_sl12_sr12 == 0x3) and (op_m1_sl14_sr14 == 0x0):
            cmd.itype = self.inames['ld']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = op_m12_sl20_sr20
            cmd[1].reg = op_m5_sl15_sr15
        elif (op_m2_sl0_sr0 == 0x3) and (op_m3_sl2_sr2 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x3) and (op_m1_sl14_sr14 == 0x0):
            cmd.itype = self.inames['sd']
            cmd[0].type = o_displ
            cmd[0].addr = (op_m5_sl7_sr7 | op_m7_sl25_sr20)
            cmd[0].reg = op_m5_sl15_sr15
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl20_sr20
            cmd[1].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m2_sl3_sr3 == 0x3) and (op_m2_sl5_sr5 == 0x0) and (op_m3_sl12_sr12 == 0x0):
            cmd.itype = self.inames['addiw']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = SIGNEXT(op_m12_sl20_sr20, 12)
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m2_sl3_sr3 == 0x3) and (op_m2_sl5_sr5 == 0x0) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0) and (op_m7_sl25_sr25 == 0x0):
            cmd.itype = self.inames['slliw']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m2_sl3_sr3 == 0x3) and (op_m2_sl5_sr5 == 0x0) and (op_m1_sl12_sr12 == 0x1) and (op_m1_sl13_sr13 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m7_sl25_sr25 == 0x0):
            cmd.itype = self.inames['srliw']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m2_sl3_sr3 == 0x3) and (op_m2_sl5_sr5 == 0x0) and (op_m1_sl12_sr12 == 0x1) and (op_m1_sl13_sr13 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m5_sl25_sr25 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['sraiw']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m3_sl3_sr3 == 0x7) and (op_m1_sl6_sr6 == 0x0) and (op_m3_sl12_sr12 == 0x0) and (op_m7_sl25_sr25 == 0x0):
            cmd.itype = self.inames['addw']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m3_sl3_sr3 == 0x7) and (op_m1_sl6_sr6 == 0x0) and (op_m3_sl12_sr12 == 0x0) and (op_m5_sl25_sr25 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['subw']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m3_sl3_sr3 == 0x7) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0) and (op_m7_sl25_sr25 == 0x0):
            cmd.itype = self.inames['sllw']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m3_sl3_sr3 == 0x7) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x1) and (op_m1_sl13_sr13 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m7_sl25_sr25 == 0x0):
            cmd.itype = self.inames['srlw']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m3_sl3_sr3 == 0x7) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x1) and (op_m1_sl13_sr13 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m5_sl25_sr25 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['sraw']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m5_sl2_sr2 == 0x0) and (op_m3_sl12_sr12 == 0x7):
            cmd.itype = self.inames['ldu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = op_m12_sl20_sr20
            cmd[1].reg = op_m5_sl15_sr15
        elif (op_m4_sl0_sr0 == 0xf) and (op_m3_sl4_sr4 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0):
            cmd.itype = self.inames['lq']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = op_m12_sl20_sr20
            cmd[1].reg = op_m5_sl15_sr15
        elif (op_m2_sl0_sr0 == 0x3) and (op_m3_sl2_sr2 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1):
            cmd.itype = self.inames['sq']
            cmd[0].type = o_displ
            cmd[0].addr = (op_m5_sl7_sr7 | op_m7_sl25_sr20)
            cmd[0].reg = op_m5_sl15_sr15
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl20_sr20
            cmd[1].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m2_sl3_sr3 == 0x3) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m3_sl12_sr12 == 0x0):
            cmd.itype = self.inames['addid']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = SIGNEXT(op_m12_sl20_sr20, 12)
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m2_sl3_sr3 == 0x3) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['sllid']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = op_m6_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m2_sl3_sr3 == 0x3) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x1) and (op_m1_sl13_sr13 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['srlid']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = op_m6_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m2_sl3_sr3 == 0x3) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x1) and (op_m1_sl13_sr13 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m4_sl26_sr26 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['sraid']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = op_m6_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m4_sl3_sr3 == 0xf) and (op_m3_sl12_sr12 == 0x0) and (op_m7_sl25_sr25 == 0x0):
            cmd.itype = self.inames['addd']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m4_sl3_sr3 == 0xf) and (op_m3_sl12_sr12 == 0x0) and (op_m5_sl25_sr25 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['subd']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m4_sl3_sr3 == 0xf) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0) and (op_m7_sl25_sr25 == 0x0):
            cmd.itype = self.inames['slld']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m4_sl3_sr3 == 0xf) and (op_m1_sl12_sr12 == 0x1) and (op_m1_sl13_sr13 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m7_sl25_sr25 == 0x0):
            cmd.itype = self.inames['srld']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m4_sl3_sr3 == 0xf) and (op_m1_sl12_sr12 == 0x1) and (op_m1_sl13_sr13 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m5_sl25_sr25 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['srad']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m2_sl4_sr4 == 0x3) and (op_m1_sl6_sr6 == 0x0) and (op_m3_sl12_sr12 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['mul']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m2_sl4_sr4 == 0x3) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['mulh']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m2_sl4_sr4 == 0x3) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['mulhsu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m2_sl4_sr4 == 0x3) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x3) and (op_m1_sl14_sr14 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['mulhu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m2_sl4_sr4 == 0x3) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m1_sl25_sr25 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['div']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m2_sl4_sr4 == 0x3) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x1) and (op_m1_sl13_sr13 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m1_sl25_sr25 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['divu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m2_sl4_sr4 == 0x3) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m2_sl13_sr13 == 0x3) and (op_m1_sl25_sr25 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['rem']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m2_sl4_sr4 == 0x3) and (op_m1_sl6_sr6 == 0x0) and (op_m3_sl12_sr12 == 0x7) and (op_m1_sl25_sr25 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['remu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m3_sl3_sr3 == 0x7) and (op_m1_sl6_sr6 == 0x0) and (op_m3_sl12_sr12 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['mulw']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m3_sl3_sr3 == 0x7) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m1_sl25_sr25 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['divw']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m3_sl3_sr3 == 0x7) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x1) and (op_m1_sl13_sr13 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m1_sl25_sr25 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['divuw']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m3_sl3_sr3 == 0x7) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m2_sl13_sr13 == 0x3) and (op_m1_sl25_sr25 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['remw']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m3_sl3_sr3 == 0x7) and (op_m1_sl6_sr6 == 0x0) and (op_m3_sl12_sr12 == 0x7) and (op_m1_sl25_sr25 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['remuw']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m4_sl3_sr3 == 0xf) and (op_m3_sl12_sr12 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['muld']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m4_sl3_sr3 == 0xf) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m1_sl25_sr25 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['divd']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m4_sl3_sr3 == 0xf) and (op_m1_sl12_sr12 == 0x1) and (op_m1_sl13_sr13 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m1_sl25_sr25 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['divud']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m4_sl3_sr3 == 0xf) and (op_m1_sl12_sr12 == 0x0) and (op_m2_sl13_sr13 == 0x3) and (op_m1_sl25_sr25 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['remd']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m4_sl3_sr3 == 0xf) and (op_m3_sl12_sr12 == 0x7) and (op_m1_sl25_sr25 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['remud']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0) and (op_m5_sl20_sr20 == 0x0) and (op_m1_sl27_sr27 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m3_sl29_sr29 == 0x0):
            cmd.itype = self.inames['lr.w']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0) and (op_m2_sl27_sr27 == 0x3) and (op_m3_sl29_sr29 == 0x0):
            cmd.itype = self.inames['sc.w']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0) and (op_m1_sl27_sr27 == 0x1) and (op_m4_sl28_sr28 == 0x0):
            cmd.itype = self.inames['amoswap.w']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0) and (op_m5_sl27_sr27 == 0x0):
            cmd.itype = self.inames['amoadd.w']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0) and (op_m2_sl27_sr27 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['amoxor.w']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0) and (op_m3_sl27_sr27 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['amoor.w']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0) and (op_m2_sl27_sr27 == 0x0) and (op_m2_sl29_sr29 == 0x3) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['amoand.w']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0) and (op_m4_sl27_sr27 == 0x0) and (op_m1_sl31_sr31 == 0x1):
            cmd.itype = self.inames['amomin.w']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0) and (op_m2_sl27_sr27 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m1_sl30_sr30 == 0x0) and (op_m1_sl31_sr31 == 0x1):
            cmd.itype = self.inames['amomax.w']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0) and (op_m3_sl27_sr27 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['amominu.w']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0) and (op_m2_sl27_sr27 == 0x0) and (op_m3_sl29_sr29 == 0x7):
            cmd.itype = self.inames['amomaxu.w']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x3) and (op_m1_sl14_sr14 == 0x0) and (op_m5_sl20_sr20 == 0x0) and (op_m1_sl27_sr27 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m3_sl29_sr29 == 0x0):
            cmd.itype = self.inames['lr.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x3) and (op_m1_sl14_sr14 == 0x0) and (op_m2_sl27_sr27 == 0x3) and (op_m3_sl29_sr29 == 0x0):
            cmd.itype = self.inames['sc.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x3) and (op_m1_sl14_sr14 == 0x0) and (op_m1_sl27_sr27 == 0x1) and (op_m4_sl28_sr28 == 0x0):
            cmd.itype = self.inames['amoswap.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x3) and (op_m1_sl14_sr14 == 0x0) and (op_m5_sl27_sr27 == 0x0):
            cmd.itype = self.inames['amoadd.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x3) and (op_m1_sl14_sr14 == 0x0) and (op_m2_sl27_sr27 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['amoxor.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x3) and (op_m1_sl14_sr14 == 0x0) and (op_m3_sl27_sr27 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['amoor.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x3) and (op_m1_sl14_sr14 == 0x0) and (op_m2_sl27_sr27 == 0x0) and (op_m2_sl29_sr29 == 0x3) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['amoand.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x3) and (op_m1_sl14_sr14 == 0x0) and (op_m4_sl27_sr27 == 0x0) and (op_m1_sl31_sr31 == 0x1):
            cmd.itype = self.inames['amomin.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x3) and (op_m1_sl14_sr14 == 0x0) and (op_m2_sl27_sr27 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m1_sl30_sr30 == 0x0) and (op_m1_sl31_sr31 == 0x1):
            cmd.itype = self.inames['amomax.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x3) and (op_m1_sl14_sr14 == 0x0) and (op_m3_sl27_sr27 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['amominu.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x3) and (op_m1_sl14_sr14 == 0x0) and (op_m2_sl27_sr27 == 0x0) and (op_m3_sl29_sr29 == 0x7):
            cmd.itype = self.inames['amomaxu.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m5_sl20_sr20 == 0x0) and (op_m1_sl27_sr27 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m3_sl29_sr29 == 0x0):
            cmd.itype = self.inames['lr.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m2_sl27_sr27 == 0x3) and (op_m3_sl29_sr29 == 0x0):
            cmd.itype = self.inames['sc.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m1_sl27_sr27 == 0x1) and (op_m4_sl28_sr28 == 0x0):
            cmd.itype = self.inames['amoswap.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m5_sl27_sr27 == 0x0):
            cmd.itype = self.inames['amoadd.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m2_sl27_sr27 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['amoxor.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m3_sl27_sr27 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['amoor.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m2_sl27_sr27 == 0x0) and (op_m2_sl29_sr29 == 0x3) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['amoand.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m4_sl27_sr27 == 0x0) and (op_m1_sl31_sr31 == 0x1):
            cmd.itype = self.inames['amomin.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m2_sl27_sr27 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m1_sl30_sr30 == 0x0) and (op_m1_sl31_sr31 == 0x1):
            cmd.itype = self.inames['amomax.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m3_sl27_sr27 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['amominu.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m1_sl4_sr4 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1) and (op_m2_sl27_sr27 == 0x0) and (op_m3_sl29_sr29 == 0x7):
            cmd.itype = self.inames['amomaxu.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m3_sl4_sr4 == 0x7) and (op_m25_sl7_sr7 == 0x0):
            cmd.itype = self.inames['ecall']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m3_sl4_sr4 == 0x7) and (op_m13_sl7_sr7 == 0x0) and (op_m1_sl20_sr20 == 0x1) and (op_m11_sl21_sr21 == 0x0):
            cmd.itype = self.inames['ebreak']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m3_sl4_sr4 == 0x7) and (op_m14_sl7_sr7 == 0x0) and (op_m1_sl21_sr21 == 0x1) and (op_m10_sl22_sr22 == 0x0):
            cmd.itype = self.inames['uret']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m3_sl4_sr4 == 0x7) and (op_m14_sl7_sr7 == 0x0) and (op_m1_sl21_sr21 == 0x1) and (op_m6_sl22_sr22 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m3_sl29_sr29 == 0x0):
            cmd.itype = self.inames['sret']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m3_sl4_sr4 == 0x7) and (op_m14_sl7_sr7 == 0x0) and (op_m1_sl21_sr21 == 0x1) and (op_m7_sl22_sr22 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['hret']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m3_sl4_sr4 == 0x7) and (op_m14_sl7_sr7 == 0x0) and (op_m1_sl21_sr21 == 0x1) and (op_m6_sl22_sr22 == 0x0) and (op_m2_sl28_sr28 == 0x3) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['mret']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m3_sl4_sr4 == 0x7) and (op_m14_sl7_sr7 == 0x0) and (op_m1_sl21_sr21 == 0x1) and (op_m2_sl22_sr22 == 0x0) and (op_m2_sl24_sr24 == 0x3) and (op_m1_sl26_sr26 == 0x0) and (op_m4_sl27_sr27 == 0xf) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['dret']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m3_sl4_sr4 == 0x7) and (op_m8_sl7_sr7 == 0x0) and (op_m2_sl20_sr20 == 0x0) and (op_m1_sl22_sr22 == 0x1) and (op_m5_sl23_sr23 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m3_sl29_sr29 == 0x0):
            cmd.itype = self.inames['sfence.vm']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl15_sr15
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m3_sl4_sr4 == 0x7) and (op_m13_sl7_sr7 == 0x0) and (op_m1_sl20_sr20 == 0x1) and (op_m1_sl21_sr21 == 0x0) and (op_m1_sl22_sr22 == 0x1) and (op_m5_sl23_sr23 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m3_sl29_sr29 == 0x0):
            cmd.itype = self.inames['wfi']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m3_sl4_sr4 == 0x7) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0):
            cmd.itype = self.inames['csrrw']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = op_m12_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m3_sl4_sr4 == 0x7) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0):
            cmd.itype = self.inames['csrrs']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = op_m12_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m3_sl4_sr4 == 0x7) and (op_m2_sl12_sr12 == 0x3) and (op_m1_sl14_sr14 == 0x0):
            cmd.itype = self.inames['csrrc']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl15_sr15
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = op_m12_sl20_sr20
            cmd[2].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m3_sl4_sr4 == 0x7) and (op_m1_sl12_sr12 == 0x1) and (op_m1_sl13_sr13 == 0x0) and (op_m1_sl14_sr14 == 0x1):
            cmd.itype = self.inames['csrrwi']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_imm
            cmd[1].value = op_m17_sl15_sr15
            cmd[1].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m3_sl4_sr4 == 0x7) and (op_m1_sl12_sr12 == 0x0) and (op_m2_sl13_sr13 == 0x3):
            cmd.itype = self.inames['csrrsi']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_imm
            cmd[1].value = op_m17_sl15_sr15
            cmd[1].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m3_sl4_sr4 == 0x7) and (op_m3_sl12_sr12 == 0x7):
            cmd.itype = self.inames['csrrci']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
            cmd[1].type = o_imm
            cmd[1].value = op_m17_sl15_sr15
            cmd[1].dtyp = dt_word
        elif (op_m3_sl0_sr0 == 0x7) and (op_m4_sl3_sr3 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0):
            cmd.itype = self.inames['flw']
            cmd[0].type = o_displ
            cmd[0].addr = op_m12_sl20_sr20
            cmd[0].reg = op_m5_sl15_sr15
        elif (op_m3_sl0_sr0 == 0x7) and (op_m2_sl3_sr3 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0):
            cmd.itype = self.inames['fsw']
            cmd[0].type = o_displ
            cmd[0].addr = (op_m5_sl7_sr7 | op_m7_sl25_sr20)
            cmd[0].reg = op_m5_sl15_sr15
        elif (op_m2_sl0_sr0 == 0x3) and (op_m4_sl2_sr2 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl25_sr25 == 0x0):
            cmd.itype = self.inames['fmadd.s']
        elif (op_m3_sl0_sr0 == 0x7) and (op_m3_sl3_sr3 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl25_sr25 == 0x0):
            cmd.itype = self.inames['fmsub.s']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m1_sl3_sr3 == 0x1) and (op_m2_sl4_sr4 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl25_sr25 == 0x0):
            cmd.itype = self.inames['fnmsub.s']
        elif (op_m4_sl0_sr0 == 0xf) and (op_m2_sl4_sr4 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl25_sr25 == 0x0):
            cmd.itype = self.inames['fnmadd.s']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m7_sl25_sr25 == 0x0):
            cmd.itype = self.inames['fadd.s']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl25_sr25 == 0x0) and (op_m1_sl27_sr27 == 0x1) and (op_m4_sl28_sr28 == 0x0):
            cmd.itype = self.inames['fsub.s']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m3_sl25_sr25 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m3_sl29_sr29 == 0x0):
            cmd.itype = self.inames['fmul.s']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl25_sr25 == 0x0) and (op_m2_sl27_sr27 == 0x3) and (op_m3_sl29_sr29 == 0x0):
            cmd.itype = self.inames['fdiv.s']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m3_sl12_sr12 == 0x0) and (op_m4_sl25_sr25 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['fsgnj.s']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0) and (op_m4_sl25_sr25 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['fsgnjn.s']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0) and (op_m4_sl25_sr25 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['fsgnjx.s']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m3_sl12_sr12 == 0x0) and (op_m2_sl25_sr25 == 0x0) and (op_m1_sl27_sr27 == 0x1) and (op_m1_sl28_sr28 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['fmin.s']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0) and (op_m2_sl25_sr25 == 0x0) and (op_m1_sl27_sr27 == 0x1) and (op_m1_sl28_sr28 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['fmax.s']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m7_sl20_sr20 == 0x0) and (op_m2_sl27_sr27 == 0x3) and (op_m1_sl29_sr29 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['fsqrt.s']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m3_sl12_sr12 == 0x0) and (op_m4_sl25_sr25 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m1_sl30_sr30 == 0x0) and (op_m1_sl31_sr31 == 0x1):
            cmd.itype = self.inames['fle.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0) and (op_m4_sl25_sr25 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m1_sl30_sr30 == 0x0) and (op_m1_sl31_sr31 == 0x1):
            cmd.itype = self.inames['flt.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0) and (op_m4_sl25_sr25 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m1_sl30_sr30 == 0x0) and (op_m1_sl31_sr31 == 0x1):
            cmd.itype = self.inames['feq.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m10_sl20_sr20 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.w.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl20_sr20 == 0x1) and (op_m9_sl21_sr21 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.wu.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m8_sl20_sr20 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m1_sl29_sr29 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.s.w']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl15_sr15
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl20_sr20 == 0x1) and (op_m7_sl21_sr21 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m1_sl29_sr29 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.s.wu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl15_sr15
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m3_sl12_sr12 == 0x0) and (op_m9_sl20_sr20 == 0x0) and (op_m3_sl29_sr29 == 0x7):
            cmd.itype = self.inames['fmv.x.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0) and (op_m9_sl20_sr20 == 0x0) and (op_m3_sl29_sr29 == 0x7):
            cmd.itype = self.inames['fclass.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m3_sl12_sr12 == 0x0) and (op_m8_sl20_sr20 == 0x0) and (op_m4_sl28_sr28 == 0xf):
            cmd.itype = self.inames['fmv.s.x']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl15_sr15
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl20_sr20 == 0x0) and (op_m1_sl21_sr21 == 0x1) and (op_m8_sl22_sr22 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.l.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl20_sr20 == 0x3) and (op_m8_sl22_sr22 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.lu.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl20_sr20 == 0x0) and (op_m1_sl21_sr21 == 0x1) and (op_m6_sl22_sr22 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m1_sl29_sr29 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.s.l']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl15_sr15
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl20_sr20 == 0x3) and (op_m6_sl22_sr22 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m1_sl29_sr29 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.s.lu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl15_sr15
            cmd[0].dtyp = dt_word
        elif (op_m3_sl0_sr0 == 0x7) and (op_m4_sl3_sr3 == 0x0) and (op_m2_sl12_sr12 == 0x3) and (op_m1_sl14_sr14 == 0x0):
            cmd.itype = self.inames['fld']
            cmd[0].type = o_displ
            cmd[0].addr = op_m12_sl20_sr20
            cmd[0].reg = op_m5_sl15_sr15
        elif (op_m3_sl0_sr0 == 0x7) and (op_m2_sl3_sr3 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x3) and (op_m1_sl14_sr14 == 0x0):
            cmd.itype = self.inames['fsd']
            cmd[0].type = o_displ
            cmd[0].addr = (op_m5_sl7_sr7 | op_m7_sl25_sr20)
            cmd[0].reg = op_m5_sl15_sr15
        elif (op_m2_sl0_sr0 == 0x3) and (op_m4_sl2_sr2 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl25_sr25 == 0x1) and (op_m1_sl26_sr26 == 0x0):
            cmd.itype = self.inames['fmadd.d']
        elif (op_m3_sl0_sr0 == 0x7) and (op_m3_sl3_sr3 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl25_sr25 == 0x1) and (op_m1_sl26_sr26 == 0x0):
            cmd.itype = self.inames['fmsub.d']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m1_sl3_sr3 == 0x1) and (op_m2_sl4_sr4 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl25_sr25 == 0x1) and (op_m1_sl26_sr26 == 0x0):
            cmd.itype = self.inames['fnmsub.d']
        elif (op_m4_sl0_sr0 == 0xf) and (op_m2_sl4_sr4 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl25_sr25 == 0x1) and (op_m1_sl26_sr26 == 0x0):
            cmd.itype = self.inames['fnmadd.d']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl25_sr25 == 0x1) and (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['fadd.d']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl25_sr25 == 0x1) and (op_m1_sl26_sr26 == 0x0) and (op_m1_sl27_sr27 == 0x1) and (op_m4_sl28_sr28 == 0x0):
            cmd.itype = self.inames['fsub.d']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl25_sr25 == 0x1) and (op_m2_sl26_sr26 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m3_sl29_sr29 == 0x0):
            cmd.itype = self.inames['fmul.d']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl25_sr25 == 0x1) and (op_m1_sl26_sr26 == 0x0) and (op_m2_sl27_sr27 == 0x3) and (op_m3_sl29_sr29 == 0x0):
            cmd.itype = self.inames['fdiv.d']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m3_sl12_sr12 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m3_sl26_sr26 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['fsgnj.d']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m3_sl26_sr26 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['fsgnjn.d']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m3_sl26_sr26 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['fsgnjx.d']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m3_sl12_sr12 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m1_sl26_sr26 == 0x0) and (op_m1_sl27_sr27 == 0x1) and (op_m1_sl28_sr28 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['fmin.d']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m1_sl26_sr26 == 0x0) and (op_m1_sl27_sr27 == 0x1) and (op_m1_sl28_sr28 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['fmax.d']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl20_sr20 == 0x1) and (op_m9_sl21_sr21 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['fcvt.s.d']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m5_sl20_sr20 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m4_sl26_sr26 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['fcvt.d.s']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m5_sl20_sr20 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m1_sl26_sr26 == 0x0) and (op_m2_sl27_sr27 == 0x3) and (op_m1_sl29_sr29 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['fsqrt.d']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m3_sl12_sr12 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m3_sl26_sr26 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m1_sl30_sr30 == 0x0) and (op_m1_sl31_sr31 == 0x1):
            cmd.itype = self.inames['fle.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m3_sl26_sr26 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m1_sl30_sr30 == 0x0) and (op_m1_sl31_sr31 == 0x1):
            cmd.itype = self.inames['flt.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m3_sl26_sr26 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m1_sl30_sr30 == 0x0) and (op_m1_sl31_sr31 == 0x1):
            cmd.itype = self.inames['feq.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m5_sl20_sr20 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m4_sl26_sr26 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.w.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl20_sr20 == 0x1) and (op_m4_sl21_sr21 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m4_sl26_sr26 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.wu.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m5_sl20_sr20 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m2_sl26_sr26 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m1_sl29_sr29 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.d.w']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl15_sr15
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl20_sr20 == 0x1) and (op_m4_sl21_sr21 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m2_sl26_sr26 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m1_sl29_sr29 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.d.wu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl15_sr15
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0) and (op_m5_sl20_sr20 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m3_sl26_sr26 == 0x0) and (op_m3_sl29_sr29 == 0x7):
            cmd.itype = self.inames['fclass.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl20_sr20 == 0x0) and (op_m1_sl21_sr21 == 0x1) and (op_m3_sl22_sr22 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m4_sl26_sr26 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.l.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl20_sr20 == 0x3) and (op_m3_sl22_sr22 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m4_sl26_sr26 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.lu.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m3_sl12_sr12 == 0x0) and (op_m5_sl20_sr20 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m3_sl26_sr26 == 0x0) and (op_m3_sl29_sr29 == 0x7):
            cmd.itype = self.inames['fmv.x.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl20_sr20 == 0x0) and (op_m1_sl21_sr21 == 0x1) and (op_m3_sl22_sr22 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m2_sl26_sr26 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m1_sl29_sr29 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.d.l']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl15_sr15
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl20_sr20 == 0x3) and (op_m3_sl22_sr22 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m2_sl26_sr26 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m1_sl29_sr29 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.d.lu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl15_sr15
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m3_sl12_sr12 == 0x0) and (op_m5_sl20_sr20 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m2_sl26_sr26 == 0x0) and (op_m4_sl28_sr28 == 0xf):
            cmd.itype = self.inames['fmv.d.x']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl15_sr15
            cmd[0].dtyp = dt_word
        elif (op_m3_sl0_sr0 == 0x7) and (op_m4_sl3_sr3 == 0x0) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1):
            cmd.itype = self.inames['flq']
            cmd[0].type = o_displ
            cmd[0].addr = op_m12_sl20_sr20
            cmd[0].reg = op_m5_sl15_sr15
        elif (op_m3_sl0_sr0 == 0x7) and (op_m2_sl3_sr3 == 0x0) and (op_m1_sl5_sr5 == 0x1) and (op_m1_sl6_sr6 == 0x0) and (op_m2_sl12_sr12 == 0x0) and (op_m1_sl14_sr14 == 0x1):
            cmd.itype = self.inames['fsq']
            cmd[0].type = o_displ
            cmd[0].addr = (op_m5_sl7_sr7 | op_m7_sl25_sr20)
            cmd[0].reg = op_m5_sl15_sr15
        elif (op_m2_sl0_sr0 == 0x3) and (op_m4_sl2_sr2 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl25_sr25 == 0x3):
            cmd.itype = self.inames['fmadd.q']
        elif (op_m3_sl0_sr0 == 0x7) and (op_m3_sl3_sr3 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl25_sr25 == 0x3):
            cmd.itype = self.inames['fmsub.q']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m1_sl2_sr2 == 0x0) and (op_m1_sl3_sr3 == 0x1) and (op_m2_sl4_sr4 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl25_sr25 == 0x3):
            cmd.itype = self.inames['fnmsub.q']
        elif (op_m4_sl0_sr0 == 0xf) and (op_m2_sl4_sr4 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl25_sr25 == 0x3):
            cmd.itype = self.inames['fnmadd.q']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl25_sr25 == 0x3) and (op_m5_sl27_sr27 == 0x0):
            cmd.itype = self.inames['fadd.q']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m3_sl25_sr25 == 0x7) and (op_m4_sl28_sr28 == 0x0):
            cmd.itype = self.inames['fsub.q']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl25_sr25 == 0x3) and (op_m1_sl27_sr27 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m3_sl29_sr29 == 0x0):
            cmd.itype = self.inames['fmul.q']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m4_sl25_sr25 == 0xf) and (op_m3_sl29_sr29 == 0x0):
            cmd.itype = self.inames['fdiv.q']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m3_sl12_sr12 == 0x0) and (op_m2_sl25_sr25 == 0x3) and (op_m2_sl27_sr27 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['fsgnj.q']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0) and (op_m2_sl25_sr25 == 0x3) and (op_m2_sl27_sr27 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['fsgnjn.q']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0) and (op_m2_sl25_sr25 == 0x3) and (op_m2_sl27_sr27 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['fsgnjx.q']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m3_sl12_sr12 == 0x0) and (op_m3_sl25_sr25 == 0x7) and (op_m1_sl28_sr28 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['fmin.q']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0) and (op_m3_sl25_sr25 == 0x7) and (op_m1_sl28_sr28 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m2_sl30_sr30 == 0x0):
            cmd.itype = self.inames['fmax.q']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl20_sr20 == 0x3) and (op_m8_sl22_sr22 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['fcvt.s.q']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m5_sl20_sr20 == 0x0) and (op_m2_sl25_sr25 == 0x3) and (op_m3_sl27_sr27 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['fcvt.q.s']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl20_sr20 == 0x3) and (op_m3_sl22_sr22 == 0x0) and (op_m1_sl25_sr25 == 0x1) and (op_m4_sl26_sr26 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['fcvt.d.q']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl20_sr20 == 0x1) and (op_m4_sl21_sr21 == 0x0) and (op_m2_sl25_sr25 == 0x3) and (op_m3_sl27_sr27 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['fcvt.q.d']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m5_sl20_sr20 == 0x0) and (op_m4_sl25_sr25 == 0xf) and (op_m1_sl29_sr29 == 0x0) and (op_m1_sl30_sr30 == 0x1) and (op_m1_sl31_sr31 == 0x0):
            cmd.itype = self.inames['fsqrt.q']
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m3_sl12_sr12 == 0x0) and (op_m2_sl25_sr25 == 0x3) and (op_m2_sl27_sr27 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m1_sl30_sr30 == 0x0) and (op_m1_sl31_sr31 == 0x1):
            cmd.itype = self.inames['fle.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0) and (op_m2_sl25_sr25 == 0x3) and (op_m2_sl27_sr27 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m1_sl30_sr30 == 0x0) and (op_m1_sl31_sr31 == 0x1):
            cmd.itype = self.inames['flt.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x0) and (op_m1_sl13_sr13 == 0x1) and (op_m1_sl14_sr14 == 0x0) and (op_m2_sl25_sr25 == 0x3) and (op_m2_sl27_sr27 == 0x0) and (op_m1_sl29_sr29 == 0x1) and (op_m1_sl30_sr30 == 0x0) and (op_m1_sl31_sr31 == 0x1):
            cmd.itype = self.inames['feq.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m5_sl20_sr20 == 0x0) and (op_m2_sl25_sr25 == 0x3) and (op_m3_sl27_sr27 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.w.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl20_sr20 == 0x1) and (op_m4_sl21_sr21 == 0x0) and (op_m2_sl25_sr25 == 0x3) and (op_m3_sl27_sr27 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.wu.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m5_sl20_sr20 == 0x0) and (op_m2_sl25_sr25 == 0x3) and (op_m1_sl27_sr27 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m1_sl29_sr29 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.q.w']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl15_sr15
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl20_sr20 == 0x1) and (op_m4_sl21_sr21 == 0x0) and (op_m2_sl25_sr25 == 0x3) and (op_m1_sl27_sr27 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m1_sl29_sr29 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.q.wu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl15_sr15
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl12_sr12 == 0x1) and (op_m2_sl13_sr13 == 0x0) and (op_m5_sl20_sr20 == 0x0) and (op_m2_sl25_sr25 == 0x3) and (op_m2_sl27_sr27 == 0x0) and (op_m3_sl29_sr29 == 0x7):
            cmd.itype = self.inames['fclass.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl20_sr20 == 0x0) and (op_m1_sl21_sr21 == 0x1) and (op_m3_sl22_sr22 == 0x0) and (op_m2_sl25_sr25 == 0x3) and (op_m3_sl27_sr27 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.l.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl20_sr20 == 0x3) and (op_m3_sl22_sr22 == 0x0) and (op_m2_sl25_sr25 == 0x3) and (op_m3_sl27_sr27 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.lu.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m1_sl20_sr20 == 0x0) and (op_m1_sl21_sr21 == 0x1) and (op_m3_sl22_sr22 == 0x0) and (op_m2_sl25_sr25 == 0x3) and (op_m1_sl27_sr27 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m1_sl29_sr29 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.q.l']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl15_sr15
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m2_sl20_sr20 == 0x3) and (op_m3_sl22_sr22 == 0x0) and (op_m2_sl25_sr25 == 0x3) and (op_m1_sl27_sr27 == 0x0) and (op_m1_sl28_sr28 == 0x1) and (op_m1_sl29_sr29 == 0x0) and (op_m2_sl30_sr30 == 0x3):
            cmd.itype = self.inames['fcvt.q.lu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl15_sr15
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m3_sl12_sr12 == 0x0) and (op_m5_sl20_sr20 == 0x0) and (op_m2_sl25_sr25 == 0x3) and (op_m2_sl27_sr27 == 0x0) and (op_m3_sl29_sr29 == 0x7):
            cmd.itype = self.inames['fmv.x.q']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl7_sr7
            cmd[0].dtyp = dt_word
        elif (op_m2_sl0_sr0 == 0x3) and (op_m2_sl2_sr2 == 0x0) and (op_m1_sl4_sr4 == 0x1) and (op_m1_sl5_sr5 == 0x0) and (op_m1_sl6_sr6 == 0x1) and (op_m3_sl12_sr12 == 0x0) and (op_m5_sl20_sr20 == 0x0) and (op_m2_sl25_sr25 == 0x3) and (op_m1_sl27_sr27 == 0x0) and (op_m4_sl28_sr28 == 0xf):
            cmd.itype = self.inames['fmv.q.x']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl15_sr15
            cmd[0].dtyp = dt_word



        return cmd.size

    def ana(self):
        try:
            return self._ana()
        except DecodingError:
            return 0

    def _emu_operand(self, op):
        if op.type == o_mem:
            ua_dodata2(0, op.addr, op.dtyp)
            ua_add_dref(0, op.addr, dr_R)
        elif op.type == o_near:
            if self.cmd.get_canon_feature() & CF_CALL:
                fl = fl_CN
                ua_add_cref(0, op.addr, fl)
            else:
                fl = fl_JN
                self.delayed_jmp[self.cmd.ea+4] = {'addr': op.addr, 'fl': fl}
            
    
    #lui            a0, 65536
    #addi           a0, a0, 320 
    # add data offset
    def simplify(self):

        if self.last_is_lui != None and self.cmd.itype == self.inames['addi']:
            if self.cmd[0].reg == self.cmd[1].reg and self.cmd[0].reg == self.last_is_lui:
                ua_add_dref(2, 0x10000+self.cmd[2].value, dr_R)

        if self.cmd.itype == self.inames['lui'] and self.cmd[1].value == 0x10:
            self.last_is_lui = self.cmd[0].reg
        else:
            self.last_is_lui = None


    def emu(self):
        cmd = self.cmd
        ft = cmd.get_canon_feature()
        if ft & CF_USE1:
            self._emu_operand(cmd[0])
        if ft & CF_USE2:
            self._emu_operand(cmd[1])
        if ft & CF_USE3:
            self._emu_operand(cmd[2])
        if ft & CF_USE4:
            self._emu_operand(cmd[3])
        if not ft & CF_STOP:
            ua_add_cref(0, cmd.ea + cmd.size, fl_F)

        if self.cmd.ea in self.delayed_jmp:
            ua_add_cref(0, self.delayed_jmp[self.cmd.ea]['addr'], self.delayed_jmp[self.cmd.ea]['fl'])

        self.simplify()
        return True

    def outop(self, op):

        optype = op.type
        fl     = op.specval

        if optype == o_reg:
            out_register(self.regNames[op.reg])

        elif optype == o_imm:
            OutValue(op, OOFW_IMM | OOFW_32 | OOF_SIGNED)

        elif optype in [o_near, o_mem]:
            if optype == o_mem and fl == FL_ABSOLUTE:
                out_symbol('&')
            r = out_name_expr(op, op.addr, BADADDR)
            if not r:
                out_tagon(COLOR_ERROR)
                OutLong(op.addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueSet(Q_noName, self.cmd.ea)

        elif optype == o_displ:
            # 16-bit index is signed
            OutValue(op, OOF_ADDR | OOFW_16 | OOF_SIGNED)
            out_symbol('(')
            out_register(self.regNames[op.reg])
            out_symbol(')')

        elif optype == o_phrase:
            out_symbol('@')
            out_register(self.regNames[op.reg])
        else:
            return False

        return True

    def out(self):
        cmd = self.cmd
        ft = cmd.get_canon_feature()
        buf = init_output_buffer(1024)
        OutMnem(15)
        if ft & CF_USE1:
            out_one_operand(0)
        if ft & CF_USE2:
            OutChar(',')
            OutChar(' ')
            out_one_operand(1)
        if ft & CF_USE3:
            OutChar(',')
            OutChar(' ')
            out_one_operand(2)
        term_output_buffer()
        cvar.gl_comm = 1
        MakeLine(buf)

def PROCESSOR_ENTRY():
    return openrisc_processor_t()
