import idaapi
import ida_frame
import ida_funcs
import ida_bytes

import sark
import parse

import functioninliner


# disable unused addresses (mapped, but not under any segment -> will always be unknown)
print("DISABLING UNUSED ADDRESSES")


def has_segment(ea):
    return bool(sark.Segment(ea).name)


ea = idaapi.next_unknown(0, idaapi.BADADDR)
while ea != idaapi.BADADDR:
    if not has_segment(ea):
        print(f"disabling address {ea:#x}")
        idaapi.disable_flags(ea, ea + ida_bytes.get_item_size(ea))
    ea = idaapi.next_unknown(ea, idaapi.BADADDR)

# look for dangling clones metadata and:
# 1. remove clones for missing sources
# 2. undo patched BLs to missing clones
print("FIXING CLONES METADATA")


def get_original_bytes(start_ea, size):
    orig = bytearray()
    for ea in range(start_ea, start_ea + size):
        orig.append(idaapi.get_original_byte(ea))
    return bytes(orig)


def revert_patched_BL(src_ea, original_bytes=None):
    size = ida_bytes.get_item_size(src_ea)
    if original_bytes is None:
        original_bytes = get_original_bytes(src_ea, size)
        if original_bytes == b"\xff\xff\xff\xff":
            print(f"cannot revert patch @ {src_ea:#x}!")
            return
    else:
        assert len(original_bytes) == size

    print(f"reverting patch @ {src_ea:#x}")
    idaapi.patch_bytes(src_ea, original_bytes)

    idaapi.plan_and_wait(src_ea, src_ea + size)

    try:
        src_func = sark.Function(src_ea)
        for chunk_ea in functioninliner.unreachable_function_chunks_eas(src_func):
            idaapi.remove_func_tail(src_func._func, chunk_ea)
    except sark.exceptions.SarkNoFunction:
        pass


def is_valid_branch(src_ea, target_ea):
    if not idaapi.is_mapped(src_ea):
        return False

    src = sark.Line(src_ea)
    try:
        if src.insn.mnem == "B" and src.insn.operands[0].addr == target_ea:
            return True
    except sark.exceptions.SarkNoInstruction:
        return False


def fix_func_tail(src_ea, clone_ea):
    try:
        src_func = sark.Function(src_ea)
        clone_end_ea = sark.Segment(clone_ea).end_ea
        # we used to just call append_func_tail, but on some IDA version
        # we started getting occasional internal errors on some of these
        if src_func.ea not in functioninliner.function_chunk_parent_eas(clone_ea):
            idaapi.append_func_tail(src_func._func, clone_ea, clone_end_ea)
    except sark.exceptions.SarkNoFunction:
        pass


storage = functioninliner.ClonesStorage()
patches = sark.data.get_patched_bytes()

for func_ea, clones in list(storage.items()):
    for src_ea, clone_info in list(clones.items()):
        valid_src = is_valid_branch(src_ea, clone_info.clone_ea)

        if idaapi.is_mapped(clone_info.clone_ea):
            clone_seg_name = sark.Segment(clone_info.clone_ea).name
            parts = functioninliner.ClonesStorage.parse_storage_key(clone_seg_name)
            if parts:
                valid_target = parts["src_ea"] == src_ea
            else:
                valid_target = False
        else:
            valid_target = False

        if valid_src and valid_target:
            # make sure the clone is a proper func tail of its caller
            fix_func_tail(src_ea, clone_info.clone_ea)
            continue

        if valid_target:
            print(f"deleting clone @ {clone_info.clone_ea:#x}")
            idaapi.del_segm(clone_info.clone_ea, idaapi.SEGMOD_KILL)

        if valid_src:
            print(f"reverting patch @ {src_ea:#x}")
            revert_patched_BL(src_ea, clone_info.orig_bytes)

        del clones[src_ea]

# look for dangling clones
print("REMOVING DANGLING CLONES")


clone_ea_to_clone_info = {}
storage = functioninliner.ClonesStorage()
for func_ea, clones in storage.items():
    for src_ea, clone_info in clones.items():
        assert clone_info.clone_ea not in clone_ea_to_clone_info
        clone_ea_to_clone_info[clone_info.clone_ea] = (func_ea, src_ea, clone_info)


for seg in list(sark.segments()):
    if not seg.name.startswith("inlined_"):
        continue

    clone_ea = seg.ea

    if clone_ea in clone_ea_to_clone_info:
        continue

    parts = parse.parse(functioninliner.CLONE_NAME_FMT, seg.name)
    src_ea = parts["src_ea"]

    print(f"deleting dangling clone @ {clone_ea:#x}")
    idaapi.del_segm(clone_ea, idaapi.SEGMOD_KILL)

    if idaapi.is_mapped(src_ea) and is_valid_branch(src_ea, clone_ea):
        revert_patched_BL(src_ea)

# look for dangling patched BLs
print("UNDOING DANGLING PATCHED BLs")


def patch_size(p):
    size_bits = max(p.original.bit_length(), p.patched.bit_length())
    return (size_bits + 7) // 8


def revert_range(start_ea, size):
    for ea in range(start_ea, start_ea + size):
        idaapi.revert_byte(ea)


storage = functioninliner.ClonesStorage()

for patch in sark.data.get_patched_bytes().values():
    size = patch_size(patch)

    for l in sark.lines(patch.ea & ~0x3, patch.ea + size):
        try:
            if l.insn.mnem != "B":
                continue
        except sark.exceptions.SarkNoInstruction:
            continue

        target_ea = l.insn.operands[0].addr
        if idaapi.is_mapped(target_ea):
            continue

        revert_patched_BL(l.ea)

# reanalyze program
print("REANALYZING")
idaapi.plan_and_wait(0, idaapi.BADADDR)

# re-inline missing calls for inlined functions
print("RE-INLINING MISSING CALLS FOR INLINED FUNCTIONS")
storage = functioninliner.ClonesStorage()

for func_ea in storage.keys():
    f = sark.Function(func_ea)
    if list(functioninliner.external_callers(f)):
        functioninliner.inline_function(sark.Function(func_ea))

# recalculate SP delta for all outlined chunks
print("FIXING CLONE SP ANALYSIS")
storage = functioninliner.ClonesStorage()

for func_ea, clones in list(storage.items()):
    for src_ea, clone_info in list(clones.items()):
        clone_ea = clone_info.clone_ea
        clone_end_ea = ida_funcs.get_fchunk(clone_ea).end_ea

        pfn = ida_funcs.get_func(src_ea)
        ea = clone_ea
        while ea < clone_end_ea:
            ida_frame.recalc_spd_for_basic_block(pfn, ea)
            ea += ida_bytes.get_item_size(ea)

# reanalyze program
print("REANALYZING")
idaapi.plan_and_wait(0, idaapi.BADADDR)

print("DONE!")
