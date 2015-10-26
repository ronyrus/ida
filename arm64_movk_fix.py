"""
# ARM64 MOVK fixer

This script calculates MOV/MOVK sequence value.

## What is MOVK

MOVK instruction supposed to solve the same problem MOVT instruction solves for ARMv7.

Say, you want to load a 32/64 bits immediate value into a register. How would you do it.
One way is to store the immediate value in the memory near-by and use a LDR instruction to load it into a register.
Those data bytes that you often see at the end of the functions are exactly that, immediate values near-by.
These data bytes sometimes called "data pools" by the ARM documentation.

But, what if you don't want to load the immediate from memory. Then you have a problem, instruction sizes are 32
bits for ARMv7 (ARM) and ARMv8 (ARM64) and 16/32 bits for THUMB and THUMB2 modes. Hence, you cannot
encode a 32 bit immediate into the instruction itself.

The way this problem is solved is by introducing a special instruction, MOVT (ARMv7) and MOVK (ARMv8),
that allows you to change parts of the register without disturbing other parts and the flags.

So, for example: [MOVK X0, #0x4F43] will change only the lower 16 bits of X0 to 0x4F43, without any side effects.

MOVK instruction is defined in the following way:
    MOVK <REG>, <#immediate> [, LSL#shift]

- immediate is always 16 bits
- shift is optional
- shift have to be one the following values: 0, 16, 32, 48
- when shift is not specified it's considered to be 0
- which 16 bits are modified depends on the shift value

For example, the following sequence of instructions:
    MOV  X0, #0x1000000000000
    MOVK X0, #0x4E,LSL#16
    MOVK X0, #0x4F43
results in the X0 having the value: 0x10000004e4f43


## Why this script

IDA produces a "magic" MOV instruction for the ARMv7 MOV/MOVT pairs, presenting them as one MOV with the 32 bits immediate value.
Unfortunately, IDA does not coalesce the MOV/MOVK instructions for ARMv8. This script tries to ease the pain ...

## What the script does

The script is scanning the functions for MOV/MOVK sequences. When it finds a sequence it tries to calculate the final value.
For the example given above, the script will add the following comment on the last MOVK line: [H: 0x10000004e4f43]

The script is also using some heuristics to try and help even further.
Remember, these are only heuristics, so your millage may vary.

### ascii

Sometimes, an ascii tag is encoded into a number (32 or 64 bits). When the script detects that all
the bytes of a number are printable characters it will add the ascii representation to the comment.

Example:
    MOV  W9, #0x696D0000
    MOVK W9, #0x6734
Comment: [H: 0x696d6734 A: img4]

### decimal

When calling sleep() or delay() or something similar the immediate makes more sense when presented
as a decimal number.

Examples of comments:
    setting baud rate - [H: 0x1c200 D: 115200]
    calling had_elapse() - [H: 0x186a0 D: 100000]

### offset

If the value calculated by the script is within the IDB address range (between MinEA and MaxEA) a
data reference will be added and the comment will contain the name of the address in the IDB.

Example:
    [H: 0x83d4fb000 O: unk_83D4FB000]


## Notes

- the script preserves user comments
- there is an "undo" flag, in the code, for removing the comments added by the script.
- one can re-run the script without the undo (for example to update the offset names)


## Limitations

### Naive implementation

The script will handle only the simplest form of the sequences, i.e. the following constrains apply:
- the MOV instruction must use immediate operand and not a register
- all the instruction in the sequence must follow one another
- no intermixed sequences

From my experience this far, Apple compilers produce mostly "good" sequences while compilers used for
Android produce mostly "bad".

An example of the unsupported sequence:
- intermixed sequences
- first move is not immediate
    MOV  X1, #0x908
    MOV  X0, X1
    MOVK X1, #0xFF08,LSL#16
    MOVK X0, #0xFF08,LS

The script tries to ignore the "bad" sequences and keep fixing the "good" ones.


## TODO
- handle more sequences (intermixed, starting with register, etc.)

"""

import idc
import idaapi
import idautils
import re
import string

debug = False

"""
If all (4 or 8) bytes are printable, return the ascii of the number.
"""
def get_ascii(val, is_64):
    nbytes = 8 if is_64 else 4

    # check that every byte is printable ascii
    tmp = val
    for idx in range(nbytes):
        ch = chr(tmp & 0xff)
        tmp >>= 8

        if ch not in string.letters and ch not in string.digits:
            return None

    return ("%x" % val).decode("hex")


"""
Huristics to estimate if the decimal representation might be useful.
For example for timeouts.
"""
def get_decimal(val):
    if val % 50:
        return None
    if val > 1000000:
        return None
    return "%d" % val
    

def is_offset(val):
    if MinEA() <= val <= MaxEA():
        return val
    return None


def get_name(val):
    if not is_offset(val):
        return None

    name = Name(val)
    if not name:
        return None

    return name


def movk_remove_comment(movk_addr):
    old_comment = Comment(movk_addr)
    if not old_comment: return

    new_comment = re.sub("\[H: .*?\]", "", old_comment)

    # we might have added a new line there, let's strip it
    if new_comment != '':
        new_comment = new_comment.rstrip()

    MakeComm(movk_addr, new_comment)


def movk_add_comment(movk_addr, movk_val):

    is_64_bits = GetOpnd(movk_addr, 0).startswith("X")

    ascii_str = get_ascii(movk_val, is_64_bits)
    dec_str = get_decimal(movk_val)
    offset_str = get_name(movk_val)

    if offset_str:
        final_str = "[H: 0x%x O: %s]" % (movk_val, offset_str)
    elif ascii_str:
        final_str = "[H: 0x%x A: %s]" % (movk_val, ascii_str)
    elif dec_str:
        final_str = "[H: 0x%x D: %s]" % (movk_val, dec_str)
    else:
        final_str = "[H: 0x%x]" % movk_val

    movk_remove_comment(movk_addr) # remove our previous comment in case it's not the first time
    old_comment = Comment(movk_addr) # preserve the user comment if present

    new_comment = final_str if not old_comment else (old_comment + "\n" + final_str)
    MakeComm(movk_addr, new_comment)

    if debug: print "@ %x %s" % (movk_addr, final_str)


"""
Returns a tuple with the lask MOVK instruction address and the calculated value.
"""
def movk_seq_addr_val(seq):

    # start with the value of the MOV
    prev_val = GetOperandValue(seq[0], 1) # can MOV contain LSL construct? if yes, this is broken!

    # calculate MOVKs:
    # MOVK operands that we expect are in one of the two forms:
    #   MOVK X8, #0x4A50
    #   MOVK X8, #0x4F42,LSL#16
    for item in seq[1:]:
        imm = GetOperandValue(item, 1)
        shift = 0

        # get the shift amount
        tmp = GetOpnd(item, 1).split("LSL")
        if len(tmp) > 1:
            shift = int(tmp[1].lstrip('#'))

        # sanity: imm should be not more than 16 bits
        if (imm & ~0xffff) != 0:
            print "FAIL: immediate should be 16 bit only! @0x%x" % item
            return None, None

        # sanity: shift has to be multiples of 16
        if shift not in [0, 16, 32, 48]:
            print "FAIL: shift amount should be multiple of 16! @0x%x" % item
            return None, None

        prev_val = (prev_val & (~(0xffff << shift) & 0xffffffffffffffff)) | (imm << shift)

    return seq[-1], prev_val


def fix_movk_seq(seq, undo=False):
    movk_addr, movk_val = movk_seq_addr_val(seq)
    if movk_addr is None: return

    if undo:
        movk_remove_comment(movk_addr)
        del_dref(movk_addr, movk_val)
    else:
        movk_add_comment(movk_addr, movk_val)
        if is_offset(movk_val):
            add_dref(movk_addr, movk_val, dr_O)
            if debug: print "dref: [0x%x] -> [0x%x]" % (movk_addr, movk_val)


"""
Check of the MOV..MOVK[s] sequence is valid.
We support only the naive case when the sequence is not intermixed with other instructions.
"""
def is_movk_seq_valid(seq):

    # should start with MOV
    if GetMnem(seq[0]) != "MOV":
            print "FAIL: MOVK sequence should start with MOV instruction! @0x%0X" % seq[0]
            return False

    for idx, item in enumerate(seq):

        # check immediate operand
        if GetOpType(item, 1) != o_imm:
            print "FAIL: only immediate operands are supported! @0x%0X" % item
            return False

        # check all the items except the first one
        if idx is 0: continue

        prev_item = seq[idx - 1]
        prev_mnem = GetMnem(prev_item)

        # check that the instructions are adjacent
        if item - prev_item != 4:
            print "FAIL: something between MOVK and MOV! @0x%0X" % item
            return False

        # compare registers
        if GetOpnd(item, 0) != GetOpnd(prev_item, 0):
            print "FAIL: not the same register! @0x%0X" % item
            return False

    return True


"""
Given a list of MOV and MOVK instructions try to extract the MOV..MOVK sequences.
Returns a list of sequences (each sequence is a list as well).
"""
def split_movk_seqs(movs_list):
    movs_list.reverse()

    movk_seq_list = []
    cur_seq = []
    in_movk_seq = False
    for item in movs_list:
        if in_movk_seq:
            cur_seq.append(item)

            if GetMnem(item) == "MOV":
                cur_seq.reverse()
                if is_movk_seq_valid(cur_seq):
                    movk_seq_list.append(cur_seq)
                cur_seq = []
                in_movk_seq = False
        else:
            if GetMnem(item) == "MOVK":
                in_movk_seq = True
                cur_seq.append(item)
            else:
                pass # skip MOV when not part of the MOVK sequence

    if in_movk_seq:
        print "FAIL: MOVK sequence was not terminated by MOV!"
    return movk_seq_list


"""
Find a MOV..MOVK sequences in the function and fix/unfix the MOVKs.
"""
def fix_movk_in_func(func_ea=None, undo=False):
    if not func_ea: func_ea = idc.ScreenEA()

    movs_list = []

    # filter MOVs and MOVKs (order is important)
    for item in idautils.FuncItems(func_ea):
        if GetDisasm(item).startswith("MOV"):
            movs_list.append(item)

    for seq in split_movk_seqs(movs_list):
        fix_movk_seq(seq, undo)


def fix_movk_in_seg(seg_ea=None, undo=False):
    if not seg_ea: seg_ea = idc.ScreenEA()

    for func_ea in idautils.Functions(idc.SegStart(seg_ea), idc.SegEnd(seg_ea)):
        fix_movk_in_func(func_ea, undo)


if "__main__" == __name__:
    if True:
        print "fixing movk ..."
        fix_movk_in_seg(undo=False)
    else:
        print "fixing movk in function ..."
        fix_movk_in_func()
    print "done"
else:
    print "loading ... C00L"
