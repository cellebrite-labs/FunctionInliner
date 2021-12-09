import collections
import contextlib
import functools
import itertools
import logging
import pickle
import re
import struct
import time
import types

import idaapi
import idc

import keypatch
import netnode
import parse
import sark
import tqdm
import wrapt


# DEFINITIONS


INLINED_FUNCTION_PREFIX = "inlined_"
CLONE_NAME_FMT = "inlined_0x{func_ea:x}_for_0x{src_ea:x}"
TRACE = False


# LOGGING


class LoggerWithTrace(logging.getLoggerClass()):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if TRACE:
            # add TRACE level
            logging.TRACE = 5
            logging.addLevelName(logging.TRACE, "TRACE")

    def trace(self, msg, *args, **kwargs):
        if TRACE:
            self.log(logging.TRACE, msg, *args, **kwargs)


logger = LoggerWithTrace("FunctionInliner")


# EXCEPTIONS


class FunctionInlinerException(Exception):
    pass


class FunctionInlinerUnsupportedException(FunctionInlinerException):
    pass


class FunctionInlinerUnknownFlowException(FunctionInlinerException):
    pass


# HELPERS


@contextlib.contextmanager
def autoanalysis(enabled):
    idaapi.enable_auto(enabled)
    try:
        yield None
    finally:
        idaapi.enable_auto(not enabled)


def with_autoanalysis(enabled):
    @wrapt.decorator
    def decorator(wrapped, instance, args, kwargs):
        with autoanalysis(enabled):
            return wrapped(*args, **kwargs)
    return decorator


@contextlib.contextmanager
def wait_box(msg, hide_cancel=False):
    prefix = "HIDECANCEL\n" if hide_cancel else ""
    idaapi.show_wait_box(prefix + msg)
    try:
        yield None
    finally:
        idaapi.hide_wait_box()


def get_function_under_cursor():
    line = sark.Line()

    # abort on unmapped addresses
    if not idaapi.is_mapped(line.ea):
        return None

    # if we're on a call -> return its target
    for xref in line.xrefs_from:
        if xref.type.is_jump or xref.type.is_call:
            try:
                f = sark.Function(xref.to)
                if xref.to == f.ea:
                    return f
            except sark.exceptions.SarkNoFunction:
                return None

    # if we're on the start of a function -> return it
    try:
        func = sark.Function()
        if func.start_ea == line.ea:
            return func
    except sark.exceptions.SarkNoFunction:
        return None

    return None


def align_downwards(ea, alignment):
    return ea & ~(alignment - 1)


def align_upwards(ea, alignment):
    return align_downwards(ea + (alignment - 1), alignment)


def reanalyze_line(line):
    idaapi.plan_range(line.ea, line.end_ea)


def reanalyze_program():
    """ we used to not reanalyze the entire program, but for some reason when we surgically marked
    for reanalysis only the stuff that we've changed, sometimes the auto analysis didn't recursively
    go through to everything """
    idaapi.plan_range(0, idc.BADADDR)


def is_conditional_insn(insn):
    # is having a condition suffix
    return insn._insn.segpref != 0xe  # see module/arm/arm.hpp in the IDA SDK


def is_chunked_function(func):
    return len(list(function_chunk_eas(func))) > 1


def function_chunk_eas(func):
    ea = idc.first_func_chunk(func.ea)
    while ea != idc.BADADDR:
        yield ea
        ea = idc.next_func_chunk(func.ea, ea)


def function_chunk_lines(ea):
    start_ea = idc.get_fchunk_attr(ea, idc.FUNCATTR_START)
    end_ea = idc.get_fchunk_attr(ea, idc.FUNCATTR_END)

    ea = start_ea
    l = sark.Line(start_ea)
    while l.ea < end_ea:
        yield l
        l = l.next


def function_chunk_crefs(ea, ret_ea=None):
    start_ea = idc.get_fchunk_attr(ea, idc.FUNCATTR_START)
    end_ea = idc.get_fchunk_attr(ea, idc.FUNCATTR_END)

    for l in function_chunk_lines(ea):
        try:
            if l.insn.mnem == "RET" and ret_ea is not None:
                external_cref_eas = (ret_ea,)
            else:
                external_cref_eas = (c for c in l.crefs_from if c < start_ea or c >= end_ea)

            for target_ea in external_cref_eas:
                yield (l.ea - start_ea, target_ea)
        except sark.exceptions.SarkNoInstruction:
            if not list(l.crefs_to):
                pass  # some times there's non-code inside function chunks, e.g. jumptables
            else:
                raise  # but if there's a flow cref into it, this is bad


def function_chunk_parent_eas(ea):
    fchunk = idaapi.get_fchunk(ea)
    fpi = idaapi.func_parent_iterator_t(fchunk)
    if not fpi.first():
        return

    while True:
        yield fpi.parent()
        if not fpi.next():
            break


def containing_funcs(line):
    funcs = set()
    for parent_ea in function_chunk_parent_eas(line.ea):
        try:
            funcs.add(sark.Function(parent_ea))
        except sark.exceptions.SarkNoFunction:
            pass
    try:
        funcs.add(sark.Function(line.ea))
    except sark.exceptions.SarkNoFunction:
        pass
    return funcs


def unreachable_function_chunks_eas(func):
    # map all chunks in our function
    remaining_chunks = set()
    for start_ea in function_chunk_eas(func):
        end_ea = idc.get_fchunk_attr(start_ea, idc.FUNCATTR_END)
        remaining_chunks.add((start_ea, end_ea))

    if len(remaining_chunks) == 1:
        return

    # discard reachable chunks
    def discard_reachable_chunks(chunk):
        remaining_chunks.discard(chunk)

        for src_off, target in function_chunk_crefs(chunk[0]):
            for other_chunk in remaining_chunks:
                start_ea, end_ea = other_chunk
                if start_ea <= target < end_ea:
                    discard_reachable_chunks(other_chunk)
                    break
            if not remaining_chunks:
                break

    main_chunk = (func.start_ea, func.end_ea)
    assert main_chunk in remaining_chunks

    discard_reachable_chunks(main_chunk)

    yield from (c[0] for c in remaining_chunks)


def function_crefs(func, ret_ea=None):
    chunk_eas = list(function_chunk_eas(func))
    for chunk_ea in chunk_eas:
        for off, target_ea in function_chunk_crefs(chunk_ea, ret_ea):
            if idaapi.func_contains(func._func, target_ea):
                continue

            src_ea = chunk_ea + off
            src = sark.Line(src_ea)
            if src.insn.mnem == "BL" and target_ea == src.end_ea:
                # we have a flow xref going from a BL which is the last instruction of a function
                # chunk. this can be one of two cases:
                # 1. IDA didn't recognize that the target function is a NORET function, hence there
                #    shouldn't be a flow-xref from the BL
                # 2. after BL-ing, the source function implicitly tail-calls to the next instruction
                #    which should be another function
                # because we cannot know which of the cases is the right one, and in case it's (1),
                # the next line might be data, we'll let a heuristic decide
                if is_data_heuristic(sark.Line(target_ea)):
                    continue

            yield src_ea, target_ea


def has_function_flow_xref(line):
    for xref in line.xrefs_to:
        # we're only interested in flow xrefs
        if not xref.type.is_flow:
            continue

        # sometimes there are useless NOPs before real code, so we discard xrefs from code
        # which isn't in a function
        try:
            sark.Function(xref.frm)
        except sark.exceptions.SarkNoFunction:
            continue

        return True

    return False


def external_callers(line, functions_only=False, include_flow=False):
    funcs = containing_funcs(line)

    for xref in line.xrefs_to:
        caller = sark.Line(xref.frm)

        # skip non-code xrefs
        if not xref.type.is_code:
            continue

        # skip flow xrefs
        if not include_flow and xref.type.is_flow:
            continue

        # skip recursive calls
        caller_funcs = containing_funcs(caller)

        if funcs and caller_funcs == funcs:
            continue
        elif not caller_funcs and functions_only:
            continue

        yield caller


def linegroups(n):
    iters = [sark.lines() for _ in range(n)]
    for i, it in enumerate(iters):
        for _ in range(i):
            next(it)
    return zip(*iters)


def register_parts(r):
    w = r[0]
    n = r[1:]

    families = (
        ("W", "X"),
        ("B", "H", "S", "D", "Q")
    )

    for f in families:
        if w in f:
            return (ww + n for ww in f)
    else:
        raise FunctionInlinerException(f"encountered unknown register: {r}")


def add_comment(line, cmt, prepend=True):
    if line.comments.regular is None:
        line.comments.regular = cmt
    elif prepend:
        line.comments.regular = cmt + "\n" + line.comments.regular
    else:
        line.comments.regular = line.comments.regular + "\n" + cmt


# NETNODE


class PickleNetnode(netnode.Netnode):
    @staticmethod
    def _encode(data):
        return pickle.dumps(data)

    @staticmethod
    def _decode(data):
        return pickle.loads(data)


class RenamesStorage(PickleNetnode):
    NETNODE = "$ FunctionInliner.renames"

    RenameInfo = collections.namedtuple("RenameInfo", ("orig_name", "new_name"))

    def __init__(self):
        super().__init__(self.NETNODE)

    def __setitem__(self, func_ea, rename_info):
        if not isinstance(rename_info, RenamesStorage.RenameInfo):
            raise ValueError("value must be of type RenamesStorage.RenameInfo")
        super().__setitem__(func_ea, tuple(rename_info))

    def __getitem__(self, func_ea):
        v = super().__getitem__(func_ea)
        return RenamesStorage.RenameInfo(*v)


class SingletonUserDict(type(collections.UserDict)):
    _instance = None

    def __call__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(SingletonUserDict, cls).__call__(*args, **kwargs)
        return cls._instance


class ClonesStorage(collections.UserDict, metaclass=SingletonUserDict):
    NETNODE = "$ functioninliner.clones"

    CloneInfo = collections.namedtuple("CloneInfo", ("clone_ea", "orig_bytes"))

    class InlinedFunctionInfo(collections.UserDict):
        def __init__(self, update_callback):
            super().__init__()
            self._update_callback = update_callback

        def __setitem__(self, src_ea, clone):
            if not isinstance(clone, ClonesStorage.CloneInfo):
                raise ValueError("value must be of type ClonesStorage.CloneInfo")
            self.data[src_ea] = clone
            self._update_callback(src_ea)

        def __delitem__(self, src_ea):
            del self.data[src_ea]
            self._update_callback(src_ea)

    def __init__(self):
        super().__init__()
        self.netnode = PickleNetnode(self.NETNODE)
        self.update_from_storage()

    def update_from_storage(self):
        for k, v in self.netnode.items():
            parts = ClonesStorage.parse_storage_key(k)
            if not parts:
                continue

            func_ea = parts["func_ea"]
            src_ea = parts["src_ea"]

            func_storage = self[func_ea]
            clone_info = ClonesStorage.CloneInfo(*v)
            func_storage[src_ea] = clone_info

    @staticmethod
    def storage_key(func_ea, src_ea):
        return CLONE_NAME_FMT.format(func_ea=func_ea, src_ea=src_ea)

    @staticmethod
    def parse_storage_key(k):
        return parse.parse(CLONE_NAME_FMT, k)

    def write_to_storage(self, func_ea, src_ea):
        key = ClonesStorage.storage_key(func_ea, src_ea)
        clone_info = self.data[func_ea].get(src_ea, None)
        if clone_info is None:  # delete
            del self.netnode[key]

            # if there are no more outlined
            if not self.data[func_ea]:
                del self.data[func_ea]
        else:  # set
            self.netnode[key] = tuple(clone_info)

    def __getitem__(self, func_ea):
        if func_ea in self.data:
            return self.data[func_ea]
        else:
            update_callback = functools.partial(self.write_to_storage, func_ea)
            func_storage = ClonesStorage.InlinedFunctionInfo(update_callback)
            self.data[func_ea] = func_storage
            return func_storage

    def __setitem__(self, k, v):
        raise RuntimeError("Do not try setting a value directly, but rather get its value as with "
                           "a defaultdict")

    def __delitem__(self, func_ea):
        for src_ea, _ in self[func_ea]:
            key = ClonesStorage.storage_key(func_ea, src_ea)
            del self.netnode[key]

        del self.data[func_ea]


# FUNCTION INLINING


def get_cloned_function(ea):
    seg = sark.Segment(ea)
    if not seg.name:
        return None

    parts = parse.parse(CLONE_NAME_FMT, seg.name)
    if not parts:
        return None

    return sark.Function(parts["func_ea"])


def is_originally_chunked_function(func):
    for chunk_ea in function_chunk_eas(func):
        # dismiss the "main" chunk
        if chunk_ea == func.ea:
            continue

        # dismiss chunks which are inlined clones of outlined functions
        if get_cloned_function(chunk_ea):
            continue

        # we found a "real" chunk
        return True

    return False


def create_code_segment(name, size, close_to=None, page_align=False):
    if page_align:
        alignment = 0x1000
    else:
        alignment = 0x4

    size = align_upwards(size, alignment)

    segs = list(sorted(sark.segments(), key=lambda s: s.ea))

    # delete a previously cloned segment if such exists
    for s in segs:
        if s.name == name:
            idaapi.del_segm(s.start_ea, idaapi.SEGMOD_KILL)

    # map the holes between existing segments
    holes = []
    holes.append((0, segs[0].start_ea))
    for s, next_s in zip(segs, segs[1:]):
        holes.append((s.end_ea, next_s.start_ea))
    holes.append((segs[-1].end_ea, idc.BADADDR))

    # align the start and end of each hole
    holes = [(align_upwards(h[0], alignment), align_downwards(h[1], alignment)) for h in holes]

    # filter-out holes which are too small
    holes = [h for h in holes if h[1] - h[0] >= size]

    # find the hole nearest to our caller
    if close_to is None:
        hole = holes[-1]
    else:
        def hole_dist(h):
            start, end = h
            if start > close_to:
                return start - close_to
            else:
                return close_to - end - size
        hole = min(holes, key=hole_dist)

    # create the segment
    if hole[0] > close_to:
        start_ea = hole[0]
        end_ea = hole[0] + size
    else:
        start_ea = hole[1] - size
        end_ea = hole[1]

    seg_t = idaapi.segment_t()
    seg_t.start_ea = start_ea
    seg_t.end_ea = end_ea
    seg_t.align = idaapi.saRelDble
    seg_t.comb = idaapi.scPub
    seg_t.perm = idaapi.SEGPERM_EXEC | idaapi.SEGPERM_READ
    seg_t.bitness = 2  # 64 bits
    seg_t.sel = idaapi.setup_selector(0)
    seg_t.type = idaapi.SEG_CODE
    seg_t.color = idc.DEFCOLOR

    flags = idaapi.ADDSEG_NOSREG | idaapi.ADDSEG_QUIET | idaapi.ADDSEG_NOAA

    idaapi.add_segm_ex(seg_t, name, "CODE", flags)

    return sark.Segment(start_ea)


def validate_branch_displacements(func, src_ea, clone_ea, ret_ea):
    # we only go over the first function chunk since that's the one we're cloning

    max_b_displ = 0x8000000

    def b_displ(src, target):
        return abs(target - (src + 4))

    # this isn't the most accurate condition since the clone offsets may move because of
    # our translation, but we discard that. if anything, the assembly later will fail
    clone_cref_displs = (b_displ(clone_ea + src_off, target_ea) for src_off, target_ea in
                         function_chunk_crefs(func.ea, ret_ea))
    if b_displ(src_ea, clone_ea) >= max_b_displ or \
            any(displ >= max_b_displ for displ in clone_cref_displs):

        # TBH we were greedy when choosing when to create our segment, but we don't expect
        # this to fail with +-128MB of max displacement, so we didn't bother implementing
        # a better algorithm
        raise FunctionInlinerException("created clone segment is not close enough to its "
                                       "caller or one of its call targets")


def fix_outlined_function_call(src, clone_ea, clone_end_ea, func_ea, kp_asm=None):
    if kp_asm is None:
        kp_asm = keypatch.Keypatch_Asm()

    # unfortunately, we've seen cases where IDA creates a function out of our clone instead of a
    # function chunk, and this also happens sometimes when calling idaapi.auto_apply_tail.
    # therefore, we first idaapi.append_func_tail and only then patch and plan to reanalyze the
    # caller
    idaapi.append_func_tail(idaapi.get_func(src.ea), clone_ea, clone_end_ea)

    # replace the source instruction with a B to our clone
    mnem = src.insn.mnem

    if mnem == "BL":
        opcode = "B"  # BL -> B
    else:  # is_jump
        opcode = src.disasm.split(" ", 1)[0]  # extract the original opcode (incl. conditions)

    asm = f"{opcode} #{clone_ea:#x}"  # we drop PAC flags
    code = bytes(kp_asm.assemble(asm, src.ea)[0])
    assert len(code) == src.size
    idaapi.patch_bytes(src.ea, code)
    reanalyze_line(src)

    # delete the original xref
    idaapi.del_cref(src.ea, func_ea, 0)


def inline_function_call(src, func, kp_asm=None):
    storage = ClonesStorage()
    func_storage = storage[func.ea]

    if kp_asm is None:
        kp_asm = keypatch.Keypatch_Asm()

    # verify that the function isn't chunked
    if is_chunked_function(func):
        raise FunctionInlinerUnsupportedException("chunked functions are currently unsupported")

    # clone and inline the function for each of its callers
    size = func.end_ea - func.start_ea

    # create a segment for the cloned function
    seg_size = size * 2  # we put a factor of 2 here for our ADR->ADRP+ADD fixups
    seg_name = CLONE_NAME_FMT.format(func_ea=func.ea, src_ea=src.ea)
    seg = create_code_segment(seg_name, seg_size, src.ea)
    clone_ea = seg.ea

    try:
        # analyze the caller
        if src.insn.mnem == "BL":
            ret_ea = src.end_ea
        elif src.insn.mnem == "B":  # tail-call
            ret_ea = None
        else:
            raise FunctionInlinerException(f"unexpected call opcode: {src.insn.mnem}")

        # validate that the created segment is close enough for the required branches
        validate_branch_displacements(func, src.ea, clone_ea, ret_ea)

        # clone the function
        logger.debug(f"cloning to {clone_ea:#x}")
        clone_end_ea = clone_function(func, clone_ea, ret_ea, kp_asm)

        # replace the source opcode with a branch to our clone
        orig_bytes = src.bytes
        fix_outlined_function_call(src, clone_ea, clone_end_ea, func.ea, kp_asm)

        # add clone info to storage
        clone_info = ClonesStorage.CloneInfo(clone_ea, orig_bytes)
        func_storage[src.ea] = clone_info

    except:  # noqa: E722
        # remove from storage if it's already been added
        func_storage.pop(clone_ea, None)

        # undo the source patch if it's already been done
        idaapi.patch_bytes(src.ea, src.bytes)
        reanalyze_line(src)

        # remove the created segment
        idaapi.del_segm(clone_ea, idaapi.SEGMOD_KILL)

        logger.error(f"unhandled exception was raised while inlining call to {func.name} from {src.ea:#x}")
        raise

    return clone_ea


def function_chunk_inlined_functions(ea):
    start_ea = idc.get_fchunk_attr(ea, idc.FUNCATTR_START)

    for off, target_ea in function_chunk_crefs(ea):
        func = get_cloned_function(target_ea)

        if func:
            src = sark.Line(start_ea + off)
            yield (src, func)


def rename_outlined_function(func):
    storage = RenamesStorage()

    rename_info = storage.get(func.ea)
    if rename_info and func.name == rename_info.new_name:
        return

    new_name = f"outlined_{func.name}"
    rename_info = RenamesStorage.RenameInfo(func.name, new_name)

    func.name = new_name
    storage[func.ea] = rename_info


def undo_rename_outlined_function(func):
    storage = RenamesStorage()

    rename_info = storage.get(func.ea)
    if not rename_info:
        return

    if func.name == rename_info.new_name:
        func.name = rename_info.orig_name

    del storage[func.ea]


def inline_function(func, kp_asm=None):
    # verify that the function doesn't have any chunks which aren't inlined clones of outlined
    # functions
    if is_originally_chunked_function(func):
        raise FunctionInlinerUnsupportedException("chunked functions are currently unsupported")

    # find functions that we've inlined into this function
    inlined_function_calls = list(function_chunk_inlined_functions(func.ea))

    # temporarily undo inlining into our function
    for src, inlined_func in inlined_function_calls:
        logger.debug(f"temporarily undoing inlining of {inlined_func.name} into {src.ea:#x}")
        undo_inline_function_call(src, inlined_func)

    # wait for analysis of our function
    assert idaapi.auto_wait_range(func.ea, func.end_ea) >= 0

    # assert that the function is now unchunked
    assert not is_chunked_function(func)

    func_has_outgoing_crefs = bool(list(function_chunk_crefs(func.ea)))

    # inline our function into its callers
    for src in external_callers(func):
        logger.debug(f"inlining call to {func.name} from {src.ea:#x}")
        clone_ea = inline_function_call(src, func, kp_asm)

        # wait for analysis of our clone (optimization: only if needed)
        # this is both for the case we need to redo inlining into it in a bit, and also for the case
        # we're inlining all outlined functions in the IDB and we want the clones' outgoing crefs to
        # be indexed as well
        if func_has_outgoing_crefs:
            seg = sark.Segment(clone_ea)
            assert idaapi.auto_wait_range(seg.start_ea, seg.end_ea) >= 0

    # redo inlining into our function clones
    for _, inlined_func in inlined_function_calls:
        logger.debug(f"redoing inlining of {inlined_func.name} into the cloned functions")
        inline_function(inlined_func)

    # if there are no more xrefs to this function, rename it
    if not list(external_callers(func)):
        rename_outlined_function(func)


@with_autoanalysis(False)
def inline_all_functions():
    logger.info("inlining all outlined functions...")

    failed_analysis = 0
    inlined = 0
    skipped = 0
    erroronous = 0
    kp_asm = keypatch.Keypatch_Asm()

    all_funcs = list(sark.functions())

    with wait_box("finding outlined functions..."):
        outlined_funcs = []
        for func in tqdm.tqdm(all_funcs, desc="analyzing", ncols=80, unit="func"):
            idaapi.show_auto(func.ea)

            if idaapi.user_cancelled():
                return False

            logger.debug(f"analyzing {func.name}")
            try:
                if is_function_outlined(func):
                    outlined_funcs.append(func)
            except Exception:
                logger.exception(f"unhandled exception raised when trying to analyze {func.name}:")
                failed_analysis += 1

    logger.info(f"found {len(outlined_funcs)} outlined functions")
    if failed_analysis:
        logger.error(f"failed analysing {failed_analysis} functions")

    retval = True
    with wait_box("inlining all outlined functions... (this may take a few minutes)"):
        start_time = time.time()

        for func in tqdm.tqdm(outlined_funcs, desc="inlining", ncols=80, unit="func"):
            idaapi.show_auto(func.ea)

            if idaapi.user_cancelled():
                retval = False
                break

            logger.debug(f"inlining {func.name}")
            try:
                inline_function(func, kp_asm)
                inlined += 1
            except FunctionInlinerUnsupportedException:
                skipped += 1  # skip functions that we can't inline
            except Exception:
                logger.exception(f"unhandled exception raised when trying to inline {func.name}:")
                erroronous += 1

        elapsed_time = int(time.time() - start_time)

    logger.info(f"inlined a total of {inlined} functions in {elapsed_time} seconds")

    if skipped:
        logger.warning(f"skipped {skipped} unsupported functions")

    if erroronous:
        logger.error(f"failed inlining {erroronous} functions")

    return retval


def clone_insn_ret(kp_asm, line, dst_ea, ret_ea):
    assert line.insn.mnem == "RET" and not is_conditional_insn(line.insn)

    asm = f"B #{ret_ea:#x}"  # we drop PAC flags
    code = bytes(kp_asm.assemble(asm, dst_ea)[0])

    logger.trace(f"   translated to: {asm}")
    return code


def clone_insn_branch(kp_asm, line, dst_ea, func, ret_ea):
    mnem = line.insn.mnem

    # resolve the the branch target
    if mnem == "BR":
        target = None
    else:
        crefs_from = set()
        for xref in line.xrefs_from:
            if not xref.iscode:
                continue
            if xref.type.is_flow:
                continue
            crefs_from.add(xref.to)
        assert len(crefs_from) == 1
        target = crefs_from.pop()

    if target and func.start_ea <= target < func.end_ea:  # local target -> copy as-is
        logger.trace("   local target -> copied as-is")
        return line.bytes, target - func.ea

    else:  # external target -> fix it
        if is_conditional_insn(line.insn):
            raise FunctionInlinerUnsupportedException("translating conditioned tail-calls is "
                                                      "currently unsupported")

        if mnem == "BR":
            # target is the first arg even if it's an authenticated BR
            target_reg = line.insn.operands[0].text
            asm = f"BLR {target_reg}"  # we drop PAC flags
        else:
            assert mnem in ("BL", "B")
            asm = f"BL #{target:#x}"  # we drop PAC flags

        if mnem in ("B", "BR"):  # tail-call -> also add a following B back or RET
            if ret_ea:
                asm += f"\nB #{ret_ea:#x}"
            else:
                asm += "\nRET"

        code = bytes(kp_asm.assemble(asm, dst_ea)[0])

        logger.trace(f"   translated to: {asm}")
        return code, None


def clone_insn_mem(kp_asm, line, dst_ea):
    drefs_from = set(line.drefs_from)
    insn = line.insn

    if len(drefs_from) == 1:
        target_ea = drefs_from.pop()
    else:  # this may happen with LDR when the target contains another address
        assert len(drefs_from) == 2 and insn.mnem == "LDR"
        xref = [x for x in line.xrefs_from if x.type.is_read][0]
        target_ea = xref.to

    target_page = target_ea & ~0xfff
    target_offset = target_ea & 0xfff

    if is_conditional_insn(line.insn):
        raise FunctionInlinerUnsupportedException("translating conditional mem instructions is "
                                                  "currently unsupported")

    # full_mnem should be the same as insn.mnem, but compare the full one just to be on the safe side
    full_mnem = idc.print_insn_mnem(line.ea)

    if full_mnem == "ADR":
        # usually ADR is followed by NOP, because the compiler doesn't know if it'll be ADR or
        # ADRP + ADD, but we don't want to rely on it so we'll replace the single ADR with two
        # instructions

        reg = line.insn.regs.pop()
        asm = f"""
            ADRP {reg}, #{target_page:#x}
            ADD {reg}, {reg}, #{target_offset:#x}
        """
        code = bytes(kp_asm.assemble(asm, dst_ea)[0])

        logger.trace(f"   ADR -> translated to: {asm}")
        return code

    elif full_mnem == "ADRP":
        reg = line.insn.regs.pop()
        asm = f"ADRP {reg}, #{target_page:#x}"
        code = bytes(kp_asm.assemble(asm, dst_ea)[0])

        logger.trace(f"   ADRP -> translated to: {asm}")
        return code

    else:
        # we expect the rest to be e.g. LDR/STR/ADD using an address or a PAGEOFF

        # IDA won't always show "@PAGEOFF" in the disassembly, so we have to check for this case
        # manually
        found_displ = 0
        for op in line.insn.operands:
            if op.type.is_mem:
                found_displ = -1
                break
            if op.type.is_displ:
                found_displ += 1
        pageoff_flow = found_displ == 1

        if pageoff_flow:
            # the PAGEOFF shouldn't change, so we can copy as-is
            logger.trace("   PAGEOFF -> copied as-is")
            return line.bytes

        else:  # direct memory access flow
            # try finding and replacing the target operand with the fixed one
            new_ops = []
            ops_fixed = 0
            for op in insn.operands:
                if op.type.is_mem and op.addr == target_ea:
                    new_ops.append(f"#{target_ea:#x}")
                    ops_fixed += 1
                else:
                    new_ops.append(op.text)
            assert ops_fixed == 1

            # recreate the instruction
            asm = full_mnem + " " + ", ".join(new_ops)
            code = bytes(kp_asm.assemble(asm, dst_ea)[0])

            logger.trace(f"   direct memory reference -> translated to: {asm}")
            return code


def fix_cloned_branch(kp_asm, src_ea, current_target_ea, fixed_target_ea):
    # analyze this single instruction
    idc.set_flag(idc.INF_AF, idc.AF_CODE, 0)
    idaapi.create_insn(src_ea)
    idc.set_flag(idc.INF_AF, idc.AF_CODE, 1)

    line = sark.Line(src_ea)
    insn = line.insn

    # we believe that our handling here won't match all cases, but we've never even encountered
    # a case where this fixup has been required so we don't want to spend too much effort around it

    # try finding and replacing the target operand with the fixed one
    new_ops = []
    ops_fixed = 0
    for op in insn.operands:
        if op.type.is_near and op.addr == current_target_ea:
            new_ops.append(f"#{fixed_target_ea:#x}")
            ops_fixed += 1
        else:
            new_ops.append(op.text)
    assert ops_fixed == 1

    # recreate the instruction
    full_mnem = idc.print_insn_mnem(line.ea)
    asm = full_mnem + " " + ", ".join(new_ops)
    code = bytes(kp_asm.assemble(asm, line.ea)[0])

    logger.trace(f"  -> {asm}")

    assert line.size == len(code)

    # undo the analysis of this instruction and patch it
    idaapi.del_items(src_ea, idaapi.DELIT_SIMPLE, line.size)
    idaapi.patch_bytes(line.ea, code)


def clone_function(func, dst_ea, ret_ea=None, kp_asm=None):
    if kp_asm is None:
        kp_asm = keypatch.Keypatch_Asm()

    clone_ea = dst_ea

    # maps func_offset to clone_offset, for each cloned instruction
    clone_offsets = {}
    # maps source_func_offset to target_func_offset, for cloned branches which point internally
    # to the cloned function
    potential_target_fixups = {}

    # go over all instructions in the first function chunk
    for line in function_chunk_lines(func.start_ea):
        logger.trace(f"-> {line.disasm}")

        # remember where we moved it to in the clone
        func_offset = line.ea - func.ea
        clone_offset = dst_ea - clone_ea
        clone_offsets[func_offset] = clone_offset

        # clone this instruction
        try:
            assert line.is_code

            # generate some metadata about it

            is_ret = line.insn.mnem == "RET"

            is_normal_flow = False
            for xref in line.xrefs_from:
                if not xref.iscode:
                    continue

                if not xref.type.is_flow:
                    is_normal_flow = False  # at least one non-flow code xrefs -> not normal flow
                    break
                else:
                    is_normal_flow = True  # all (at least one) flow code xrefs -> normal flow

            if any(idaapi.is_mapped(ea) for ea in line.drefs_from):
                # IDA marks enum refs as drefs with top address byte set to 0xff, so we test whether
                # we have drefs for EAs that are actually mapped
                has_drefs = True
            else:
                has_drefs = False

            # identify which kind of translation we should do

            if (is_normal_flow and not has_drefs) or (is_ret and not ret_ea):  # "simple" instruction
                logger.trace("   'simple' instruction flow -> copied as-is")
                code = line.bytes

            elif is_ret and ret_ea:  # ret (and we should translate it)
                assert not has_drefs

                logger.trace("   ret flow")
                code = clone_insn_ret(kp_asm, line, dst_ea, ret_ea)

            elif not is_normal_flow:  # conditional branch, BL, or tail-call
                assert not has_drefs

                # note: we never actually encountered any outlined code with conditional branches or BLs,
                # but tail-call handling is similiar so we're keeping the logic here anyway

                logger.trace("   conditional branch, bl or tail-call flow")
                code, target_offset = clone_insn_branch(kp_asm, line, dst_ea, func, ret_ea)

                # if the new code jumps into an address internal to our cloned function, we may need
                # to fix it up afterwards (depending on how much we'll move stuff around)
                if target_offset is not None:
                    potential_target_fixups[func_offset] = target_offset

            elif has_drefs:  # memory access
                assert is_normal_flow

                # note: we never actually encountered outlined code which did direct memory access
                # but we're keeping the logic here anyway

                logger.trace("   memory access flow")
                code = clone_insn_mem(kp_asm, line, dst_ea)

            else:
                raise FunctionInlinerException("unexpected instruction")

            # write the new code to the clone

            idaapi.patch_bytes(dst_ea, code)
            dst_ea += len(code)

        except Exception:
            logger.error(f"failed to clone instruction @ {line.ea:#x}: {line.disasm}")
            raise

    # fix local branch targets if required
    for src_offset, target_offset in potential_target_fixups.items():
        src_ea = clone_ea + clone_offsets[src_offset]
        logger.trace(f"analyzing local branch at {src_ea:#x}")

        current_target_ea = src_ea + (target_offset - src_offset)
        fixed_target_ea = clone_ea + clone_offsets[target_offset]

        if current_target_ea != fixed_target_ea:
            # note: we never actually gotten to this flow in any outlined code we've inlined
            # but we're keeping the logic here anyway

            logger.trace(f"  fixing target from {current_target_ea:#x} to {fixed_target_ea:#x}")
            fix_cloned_branch(kp_asm, src_ea, current_target_ea, fixed_target_ea)
        else:
            logger.trace("  no fixing is required")

    # analyze the clone as code
    idaapi.auto_make_code(clone_ea)

    return dst_ea


# UNDO FUNCTION INLINING


def get_inlined_function_under_cursor():
    line = sark.Line()

    # abort on unmapped addresses
    if not idaapi.is_mapped(line.ea):
        return None

    # if we're on a branch/call -> analyze its target instead
    for xref in line.xrefs_from:
        if xref.type.is_jump or xref.type.is_call:
            line = sark.Line(xref.to)
            break

    # if we're in a cloned segment -> return the function it was cloned from
    seg = sark.Segment(line.ea)
    if seg is None:  # we're pointing at an old (now non-existant) line
        return None
    func = get_cloned_function(line.ea)
    if line.ea == seg.ea and func:
        return func

    # if we're on the beginning of an inlined function -> return it
    try:
        func = sark.Function()
    except sark.exceptions.SarkNoFunction:
        return None

    storage = ClonesStorage()
    if line.ea == func.ea and func.ea in storage:
        return func

    return None


def undo_inline_function_call(src, func):
    storage = ClonesStorage()
    func_storage = storage[func.ea]
    clone_info = func_storage[src.ea]

    logger.debug(f"undoing clone of {func.name} at {clone_info.clone_ea:#x} for caller at {src.ea:#x}")

    # delete the cloned function
    idaapi.del_segm(clone_info.clone_ea, idaapi.SEGMOD_KILL)

    if idaapi.is_mapped(src.ea):  # maybe this was into another clone that has been undone as well
        # revert the BL patch
        # we don't want to do idaapi.revert_byte() here, since the patched opcode may have been
        # originally patched (e.g. inlining one outlined function into another outlined function
        # that has been inlined)
        idaapi.patch_bytes(src.ea, clone_info.orig_bytes)
        reanalyze_line(src)

        # remove unreachable chunks from the calling function. this may happen in case our clone had
        # function chunks (e.g. it called other outlined functions that were inlined into it)
        src_func = sark.Function(src)
        for chunk_ea in unreachable_function_chunks_eas(src_func):
            idaapi.remove_func_tail(src_func._func, chunk_ea)

    # remove from storage
    del func_storage[src.ea]


def undo_inline_function(func):
    storage = ClonesStorage()
    func_storage = storage[func.ea]

    # pre-iterate the generator since we're deleting items inside
    for src_ea, clone_info in list(func_storage.items()):
        src = sark.Line(src_ea)
        undo_inline_function_call(src, func)

    undo_rename_outlined_function(func)


# FUNCTION EXPLORATION


def create_missing_functions():
    found = False

    # pre-iterate since we might be adding functions inside
    for func in list(sark.functions()):
        for src_ea, target_ea in function_crefs(func):
            try:
                sark.Function(target_ea)
                continue
            except sark.exceptions.SarkNoFunction:
                pass

            # the target is not inside a function, make one

            logger.debug(f"found call to non-function from {src_ea:#x} to {target_ea:#x} "
                         "-> making function")

            if idaapi.add_func(target_ea):
                found = True

    return found


def is_data_heuristic(line):
    if line.is_code:
        return False

    # data with refs (e.g. jumptable)
    if list(line.drefs_to):
        return True

    # all 00s (alignment data)
    if not any(line.bytes):
        return True

    return False


def fix_function_noret_flags():
    found = False

    def remove_noret_typeinfo(func):
        tif = idaapi.tinfo_t()
        if idaapi.get_tinfo2(func.ea, tif):
            tif_s = idaapi.print_tinfo("", 0, 0, idaapi.PRTYPE_1LINE, tif, func.name, "")
            if "__noreturn" in tif_s:
                tif_s = tif_s.replace("__noreturn", "")
                logger.debug(f"  fixing type to '{tif_s}'")
                idc.SetType(func.ea, tif_s)

    def remove_noret(func):
        assert func.is_noret
        flags = idc.get_func_flags(func.ea)
        idc.set_func_attr(func.ea, idc.FUNCATTR_FLAGS, flags & ~idaapi.FUNC_NORET)

    def is_valid_function_code(line):
        return line.is_code and list(line.crefs_to)

    def is_bad_noret_func(func):
        for xref in func.xrefs_to:
            if not xref.type.is_call:
                continue

            call = sark.Line(xref.frm)
            after_ret = call.next

            # if the function is falsly marked as NORET, there might be unexplored/unreachable code
            # after it
            if is_valid_function_code(after_ret):
                continue

            # test for some edge cases

            # if we're followed by a function with no xrefs. this shouldn't be taken as an indicator
            # since we can't differ between a function end or a tail-call into the next one
            try:
                if after_ret.is_code and sark.Function(after_ret).ea == after_ret.ea:
                    continue
            except sark.exceptions.SarkNoFunction:
                pass

            # same thing if it has a dref (fptr) -- IDA might've joined it to our function before
            # it found out that the above func is a NORET
            if list(after_ret.drefs_to):
                logger.debug(f"  found a dref to after call @ {call.ea:#x} -> stepping back")
                continue

            # same thing if it *looks* like we're followed by a function
            if after_ret.is_code and is_function_prologue(after_ret):
                logger.debug(f"  found a prologue with no xrefs after call @ {call.ea:#x} -> stepping back")
                continue

            # if we're followed by a byte with no value this definitely is a noret function
            if not idaapi.is_loaded(after_ret.ea):
                return False

            # if we're followed by data, this definitely is a noret function
            if is_data_heuristic(after_ret):
                return False

            # try reanalyzing
            reanalyze_line(call)
            assert idaapi.auto_wait_range(call.ea, after_ret.end_ea) >= 0

            # if it didn't work
            if not is_valid_function_code(after_ret):
                logger.debug(f"  found non-code/unreachable function lines after caller @ {call.ea:#x}")
                return True

        return False  # can't say

    # pre-iterate since we might be adding functions inside
    for func in list(sark.functions()):
        if not func.is_noret:
            # not a NORET function. just make sure that its type info is OK
            remove_noret_typeinfo(func)
            continue

        logger.debug(f"analyzing NORET function {func.name}")

        # estimate whether if this really is a NORET function
        if not is_bad_noret_func(func):
            continue

        logger.debug("  removing NORET flag")

        # remove NORET flag
        remove_noret(func)

        # also remove from typeinfo
        remove_noret_typeinfo(func)

        assert not is_bad_noret_func(func)

        found = True

    return found


# IDB PREPROCESSING


def detach_chunk(chunk_ea):
    # check whether we should dechunk this
    chunk = sark.Line(chunk_ea)
    if has_function_flow_xref(chunk):
        logger.debug(f"  found flow xref to {chunk_ea:#x} -> shouldn't dechunk")
        return None

    logger.debug(f"  detaching chunk @ {chunk_ea:#x}")
    chunk_end_ea = idc.get_fchunk_attr(chunk_ea, idc.FUNCATTR_END)

    # pre-iterate the generator since we're removing fchunks inside
    parents = list(function_chunk_parent_eas(chunk_ea))

    # remove the chunk from each of its parents
    for parent_ea in parents:
        logger.trace(f"    removing from parent @ {parent_ea:#x}")
        idc.remove_fchunk(parent_ea, chunk_ea)

    # create a function out of it
    idaapi.add_func(chunk_ea, chunk_end_ea)
    func = sark.Function(chunk_ea)

    # remove unreachable chunks from the parents. this may happen in case our detachee has had
    # additional function chunks
    for parent_ea in parents:
        parent_func = sark.Function(parent_ea)
        for chunk_ea in unreachable_function_chunks_eas(parent_func):
            idaapi.remove_func_tail(parent_func._func, chunk_ea)

    return func


def dechunk_functions():
    # pre-iterate since we're adding functions inside
    functions = list(sark.functions())

    for func in functions:
        if idaapi.user_cancelled():
            return False

        if not is_originally_chunked_function(func):
            continue

        logger.debug(f"dechunking {func.name}...")

        # pre-iterate the generator since we're removing fchunks inside
        for chunk_ea in list(function_chunk_eas(func)):
            if chunk_ea == func.ea:
                continue  # skip first chunk

            if get_cloned_function(chunk_ea):
                continue  # skip inlined chunks

            new_func = detach_chunk(chunk_ea)

            # add the new function for processing
            if new_func:
                functions.append(new_func)


def split_outlined_function_trampolines():
    for l in sark.lines():
        try:
            insn = l.insn
        except sark.exceptions.SarkNoInstruction:
            continue  # nothing to do here...

        if insn.mnem != "B" or is_conditional_insn(insn):
            continue  # we're looking for unconditional branches

        target_ea = insn.operands[0].addr
        if target_ea != l.end_ea:
            continue  # to the next instruction

        # check if the next instruction is already marked as a different function
        try:
            src_func = sark.Function(l)
            target_func = sark.Function(target_ea)

            if src_func != target_func:
                continue  # it's already split
        except sark.exceptions.SarkNoFunction:
            continue  # nothing to split

        # check if there are external crefs to the next instruction (i.e. someone else has it as
        # a function chunk)
        target = sark.Line(target_ea)
        if not list(external_callers(target)):
            continue  # no external cref. no benefit in splitting

        logger.debug(f"splitting trampoline from adjacent function at {target_ea:#x}")

        # split the function after this branch
        end_ea = src_func.end_ea
        idaapi.set_func_end(l.ea, target_ea)
        idaapi.add_func(target_ea, end_ea)


def make_function_chunk(line):
    to_reprocess = []

    try:
        func = sark.Function(line)

        # check whether we need to split target's chunk
        chunk_start_ea = idc.get_fchunk_attr(line.ea, idc.FUNCATTR_START)
        should_split = chunk_start_ea != line.ea

        chunk_end_ea = idc.get_fchunk_attr(line.ea, idc.FUNCATTR_END)
    except sark.exceptions.SarkNoFunction:
        func = None
        should_split = None
        chunk_end_ea = idc.BADADDR

    if should_split:
        idaapi.set_func_end(chunk_start_ea, line.ea)
        reanalyze_line(line.prev)
        to_reprocess.append(func)

    # it's important to first add it to the other callers and not the original function, otherwise
    # IDA will automatically merge it with the chunk we've just removed it from
    for caller in external_callers(line, functions_only=True, include_flow=True):
        for caller_func in containing_funcs(caller):
            if func != caller_func:
                idaapi.append_func_tail(caller_func._func, line.ea, chunk_end_ea)
                to_reprocess.append(caller_func)

    if should_split:
        # re-add it to the original function and set it as the owner
        idaapi.append_func_tail(func._func, line.ea, chunk_end_ea)
        idaapi.set_tail_owner(idaapi.get_fchunk(line.ea), func.ea)

    idaapi.plan_range(line.ea, chunk_end_ea)

    return to_reprocess


def split_function(line):
    chunk_start_ea = idc.get_fchunk_attr(line.ea, idc.FUNCATTR_START)
    chunk_end_ea = idc.get_fchunk_attr(line.ea, idc.FUNCATTR_END)

    # verify that there's no flow xref into this line
    if has_function_flow_xref(line):
        # try adding it as a function tail to src
        logger.debug(f"  found flow xref to {line.ea:#x} -> cannot split function. making function "
                     "chunk instead")
        return make_function_chunk(line)

    # if there's a flow xref back into *all* of our callers, create a function chunk instead
    line_after_chunk = sark.Line(chunk_end_ea).next
    if has_function_flow_xref(line_after_chunk):
        # accumulate all of the funcs calling us (incl. a marker for non-func callers)
        calling_funcs = set()
        for caller in external_callers(line, include_flow=True):
            caller_funcs = containing_funcs(caller)
            if not caller_funcs:
                calling_funcs.add(None)
            else:
                calling_funcs.update(caller_funcs)

        if calling_funcs == containing_funcs(line_after_chunk):
            logger.debug("  found flow xref back to all of the the callers -> making function chunk"
                         " instead")
            return make_function_chunk(line)

    # split the function
    logger.debug(f"  splitting function chunk at {line.ea:#x}")

    idaapi.set_func_end(chunk_start_ea, line.ea)
    reanalyze_line(line.prev)

    idaapi.add_func(line.ea, chunk_end_ea)
    idaapi.plan_range(line.ea, chunk_end_ea)

    return (sark.Function(line.ea), sark.Function(line.prev.ea))


def split_adjacent_functions():
    # pre-iterate since we're adding functions inside
    functions = list(sark.functions())

    while True:
        to_reprocess = []
        for func in functions:
            for src_ea, target_ea in function_crefs(func):
                src = sark.Line(src_ea)
                target = sark.Line(target_ea)

                # check whether we're jumping to the middle of another function
                try:
                    target_func = sark.Function(target.ea)
                except sark.exceptions.SarkNoFunction:
                    logger.debug(f"found flow xref from {src.ea:#x} to non-function.")
                    continue

                if target.ea == target_func.ea:
                    continue

                # if so, split the target function
                logger.debug(f"found call/branch to middle of function from {src.ea:#x} (as part of "
                             f"{func.name}) to {target.ea:#x}")
                more_to_reprocess = split_function(target)

                # add the new function for processing, and the current for reprocessing
                if more_to_reprocess:
                    to_reprocess.extend(more_to_reprocess)

        if to_reprocess:
            # wait for what we've previously done to finish analysing
            if not idaapi.auto_wait():
                return False  # auto-analysis was cancelled

            # repeat with what we need to reprocess
            functions = to_reprocess
        else:
            break


@with_autoanalysis(False)
def preprocess_idb():
    logger.info("preprocessing IDB...")

    exploration_steps = {
        "fixing erronous NORET flags on functions...": fix_function_noret_flags,
        "creating missing functions...": create_missing_functions,
    }

    for i in itertools.count():
        found = False
        with wait_box(f"exploring (iteration {i})..."):
            for msg, func in exploration_steps.items():
                logger.debug("waiting for auto-analysis to complete...")
                if not idaapi.auto_wait():
                    return False  # auto-analysis was cancelled

                logger.info(msg)
                found = found or func()

                if idaapi.user_cancelled():
                    return False
        if found:
            reanalyze_program()
        else:
            break

    preprocessing_steps = {
        "dechunking functions...": dechunk_functions,
        "splitting trampolines from adjacent functions...": split_outlined_function_trampolines,
        "splitting adjacent functions...": split_adjacent_functions,
    }

    with wait_box("preprocessing..."):
        for msg, func in preprocessing_steps.items():
            logger.debug("waiting for auto-analysis to complete...")
            if not idaapi.auto_wait():
                return False  # auto-analysis was cancelled

            logger.info(msg)
            func()

            if idaapi.user_cancelled():
                return False

    reanalyze_program()

    logger.info("preprocessing done!")
    return True


@with_autoanalysis(False)
def postprocess_idb():
    logger.info("postprocessing IDB...")

    with wait_box("waiting for auto-analysis to complete..."):
        if not idaapi.auto_wait():
            return  # auto-analysis was cancelled

    with wait_box("postprocessing..."):
        # our inlining may cause more functions to be marked as NORET so we repeat this step from
        # preprocessing
        logger.info("fixing erronous NORET flags on functions...")
        fix_function_noret_flags()

    reanalyze_program()

    logger.info("postprocessing done!")


# OUTLINED FUNCTION FINDING


def code_flow_iterator(line, forward=True, stop=None, abort_on_calls=True, dfs=False,
                       _visited_eas=None):

    func = sark.Function(line)
    if stop is None:
        if forward:
            stop = sark.Line(func.end_ea - 4)
        else:
            stop = sark.Line(func.start_ea)

    if _visited_eas is None:
        _visited_eas = set()

    while True:
        if line.ea in _visited_eas:
            break
        else:
            _visited_eas.add(line.ea)

        yield line

        # if we encounter a BL or a tail-call, this may be to an actual outlined function, and
        # therefore analysis following this code flow shouldn't treat it as an ABI-complaint
        # function and "skip" it
        if abort_on_calls:
            if any(x.type.is_code and idaapi.func_contains(func._func, x.to) for x in
                   line.xrefs_from):
                raise FunctionInlinerUnknownFlowException()

        if line == stop:
            break

        if forward:
            crefs = [x.to for x in line.xrefs_from if
                     x.type.is_code and idaapi.func_contains(func._func, x.to)]
        else:
            crefs = [x.frm for x in line.xrefs_to if
                     x.type.is_code and idaapi.func_contains(func._func, x.frm)]

        if len(crefs) == 0:
            break

        if len(crefs) > 1:
            if not dfs:
                raise FunctionInlinerUnknownFlowException()

            for cref in crefs[:-1]:
                yield from code_flow_iterator(
                    sark.Line(cref),
                    stop=stop,
                    forward=forward,
                    abort_on_calls=abort_on_calls,
                    dfs=dfs,
                    _visited_eas=_visited_eas)

            crefs = crefs[-1:]

        line = sark.Line(crefs[0])


def find_function_ends(func):
    def is_internal(ea):
        return idaapi.func_contains(func._func, ea)

    def finder(ea, visited):
        end_eas = set()

        while ea not in visited:
            visited.add(ea)
            next_eas = [next_ea for next_ea in sark.Line(ea).crefs_from if is_internal(next_ea)]

            # handle ret/tail-call
            if len(next_eas) == 0:
                end_eas.add(ea)
                break

            # handle branch to self
            if len(next_eas) == 1 and next_eas[0] == ea:
                end_eas.add(ea)
                break

            for next_ea in next_eas[1:]:
                end_eas |= finder(next_ea, visited)

            ea = next_eas[0]

        return end_eas

    end_eas = finder(func.start_ea, set())
    return map(sark.Line, end_eas)


def is_function_prologue(line):
    # check LR is signed (relevant only ARMv8.3 code which uses it)
    if line.disasm == "PACIBSP":
        return True

    # check for BTI (relevant only ARMv8.5 code which uses it)
    if line.insn.mnem == "BTI" and line.insn.operands[0].text == "c":
        return True

    # expect stack space to be allocated
    insn = line.insn
    ops = insn.operands

    potential_stored_regs = set((f"X{i}" for i in range(19, 31))) | set(("FP", "LR"))

    if insn.mnem == "SUB" and ops[0].text == "SP" and ops[1].text == "SP":
        # stack space is allocated explicitly
        stack_space = ops[-1].value
    elif insn.mnem in ("STP", "STR") and ops[-1].base == "SP" and insn.indexing_mode.is_pre and \
            all(o.text in potential_stored_regs for o in ops[:-1]):

        # stack space is allocated inline with the first store
        stack_space = struct.unpack("<q", struct.pack("<Q", ops[-1].displacement))[0]
    else:
        return False

    # expect stack space to be 16-bytes aligned
    if stack_space & 0xf:
        return False

    # stack space is not always fully filled (since maybe some was reserved for the local frame), so
    # we don't check for that

    # FP is not always set, so we don't check for that

    return True


def get_op_regs(op):
    # regular vector operands will be shown as Qn in op.regs, so we don't have
    # to treat them specially. multiple-registers are arch specific so they're not
    # parsed by sark and we have to resolve them on our own
    if op.type.is_special and op.text.startswith("{V"):
        m = re.fullmatch(r"\{V(\d+)\.\d+.\}", op.text)
        if m:
            reg = f"Q{m.group(1)}"
            return set((reg,))
        else:
            m = re.fullmatch(r"\{V(\d+)\.\d+.-V(\d+)\.\d+.\}", op.text)
            assert m
            start, end = m.groups()
            return set((f"Q{n}" for n in range(int(start), int(end) + 1)))
    # some times (e.g. register with optional shift), Sark can't parse the register properly
    elif op.type.is_special and any(t in op.text for t in (',ASR#', ',LSL#', ',LSR#', ',ROR#')):
        reg = sark.base.get_register_name(op.reg_id)
        return set((reg,))
    else:
        return op.regs


def is_insn_using_condition_flags(insn):
    if insn.mnem in ("ADC", "CSEL", "CSINC", "CSINV", "CSNEG", "CSET", "CSETM", "CINC", "CINV",
                     "CNEG", "SBC", "NGC", "FCSEL", "VSEL"):
        return True
    else:
        return is_conditional_insn(insn)


def is_insn_setting_condition_flags(insn):
    if insn.mnem in ("TST", "CMP", "CMN", "CCMP", "CCMN", "FCMP", "FCCMP", "FCMPE", "FCCMPE",
                     "VCMP", "VCMPE"):
        return True
    else:
        # is using the S suffix
        return insn._insn.auxpref & 1  # see module/arm/arm.hpp in the IDA SDK


def get_fake_condition_flags_ops(insn):
    # check whether this instruction uses/affects condition flags
    is_read = is_insn_using_condition_flags(insn)
    is_write = is_insn_setting_condition_flags(insn)

    if not (is_read or is_write):
        return tuple()

    # we don't bother with creating a fake operand per each read/set condition flag
    # so create an operand reading/writing a fake NZCV reg

    # create a fake IDA op_t
    fake_op_t = types.SimpleNamespace(
        n=-1,
        type=idaapi.o_idpspec5 + 1,  # simulated as o_cond in arm.hpp, Sark will treat as "special"
        addr=0,
        value=0,
        flags=0,
        dtype=idaapi.dt_void,
        reg=-1
    )

    # create a fake Sark Operand with fake reg/regs properties
    class OperandWithFakeReg(sark.code.instruction.Operand):
        def __init__(self, fake_reg, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._fake_reg = fake_reg

        @sark.code.instruction.Operand.reg.getter
        def reg(self):
            return self._fake_reg

        @sark.code.instruction.Operand.regs.getter
        def regs(self):
            return set((self._fake_reg,))

    op = OperandWithFakeReg("NZCV",
                            fake_op_t,
                            insn._ea,
                            insn=insn._insn,
                            write=is_write,
                            read=is_read)

    return (op,)


def get_insn_ops_with_condition_flags(insn):
    # we create fake operands for condition flags used/set by the instruction
    yield from itertools.chain(insn.operands, get_fake_condition_flags_ops(insn))


def is_function_using_uninitialized_regs(func):
    logger.trace(f"analyzing {func.name} for uninitialized reg usage")

    initialized_regs = set(("SP", "X30", "LR", "WZR", "XZR"))

    # assume arg registers are initialized
    for i in range(8):
        initialized_regs.add(f"W{i}")
        initialized_regs.add(f"X{i}")

    # callee saved regs can be STR/STP-ed but nothing else
    callee_saved_allowed_mnems = {
        "STR": "LDR",
        "STP": "LDP",
    }
    potential_callee_saved_regs = set((f"X{i}" for i in range(19, 30)))
    callee_saved_regs = dict()  # matches stored reg to (store ea, store mnem)

    # look for uninitialized reg reads
    try:
        for l in code_flow_iterator(sark.Line(func.start_ea)):
            logger.trace(f"-> {l.disasm}")

            # regs that we'll treat as initialized once done with this instruction
            new_initialized_regs = set()

            insn = l.insn
            for op in get_insn_ops_with_condition_flags(insn):
                regs = get_op_regs(op)

                # special treatment for zeroing regs with EOR
                is_eor = insn.mnem == "EOR" and \
                    insn.operands[0].text == insn.operands[1].text == insn.operands[2].text

                for r in regs:
                    if op.type.is_displ:
                        # if we're reading an initialized reg, it's all good
                        if r in initialized_regs:
                            continue

                        logger.trace(f"   found uninitialized use of {r}")
                        return True

                    if op.is_read and not is_eor:
                        # if we're reading an initialized reg, it's all good
                        if r in initialized_regs:
                            continue

                        # if an uninitialized reg is being read it's either that or that it's actually a
                        # callee saved reg, and the we're reading it to store it somewhere and reuse that
                        # register internally
                        if r in potential_callee_saved_regs and insn.mnem in callee_saved_allowed_mnems:
                            # if it's the latter case -- we'll remember it
                            callee_saved_regs[r] = (l.ea, insn.mnem)
                            logger.trace(f"   marking {r} as callee saved")
                            continue

                        logger.trace(f"   found uninitialized use of {r}")
                        return True

                    elif op.is_write:
                        if r in initialized_regs:
                            continue

                        # special treatment for registers who aren't can't be split into parts
                        if r == "NZCV":
                            logger.trace(f"   marking {r} as initialized")
                            new_initialized_regs.add(r)
                            continue

                        # mark all of the "parts" of this register as initialized
                        logger.trace(f"   marking *{r[1:]} as initialized")
                        new_initialized_regs.update(register_parts(r))

            initialized_regs |= new_initialized_regs
    except FunctionInlinerUnknownFlowException:
        logger.trace("aborting because code flow cannot be followed any longer...")
        return False

    # verify that callee saved regs are actually restored in the end
    # if not -- they were really just used and not stored
    if not callee_saved_regs:
        return False

    logger.trace("finished forward pass ; starting backwards pass")

    # some functions have multiple ends. in case one of them points to a noret function,
    # the callee saved regs may not be restored, so in case there are multiple function ends
    # we'll just skip this validation
    func_ends = list(find_function_ends(func))
    if len(func_ends) > 1:
        logger.trace("aborting because more than one function end was found...")
        return False

    # we don't have to wrap this code_flow_iterator with try-except, since if the forward-pass
    # didn't find any basic blocks, the backwards pass surely won't
    for l in code_flow_iterator(func_ends[0], forward=False):
        logger.trace(f"-> {l.disasm}")

        insn = l.insn
        for op in get_insn_ops_with_condition_flags(insn):
            for r in op.regs:
                if r not in callee_saved_regs:
                    continue

                store_ea, store_mnem = callee_saved_regs[r]
                restore_mnem = callee_saved_allowed_mnems[store_mnem]

                # the last "use" of the callee saved reg must be to restore it, mnem must match
                # the storing mnem, and the ea must be after that of the storing ea
                if not op.is_write or insn.mnem != restore_mnem or l.ea < store_ea:
                    logger.trace(f"   last use of callee saved {r} isn't restoring")
                    return True

                # it was properly restored -> forget about it
                logger.trace(f"   found restore of callee saved {r}")
                del callee_saved_regs[r]
                if not callee_saved_regs:
                    return False

    return False


def is_function_affecting_non_result_regs(func):
    logger.trace(f"analyzing {func.name} for non-result-registers effects")

    # these special regs can also be affected in the function epilogue
    result_regs = set(("SP", "X29", "X30", "LR", "WZR", "XZR"))

    for i in range(8):
        result_regs.add(f"W{i}")
        result_regs.add(f"X{i}")

    # callee saved regs can be STR/STP-ed but nothing else
    callee_saved_allowed_mnems = {
        "LDR": "STR",
        "LDP": "STP",
    }
    potential_callee_saved_regs = set((f"X{i}" for i in range(19, 29)))
    callee_saved_regs = dict()  # matches restored reg to (restore ea, restore mnem)

    # some functions have multiple ends. in case one of them points to a noret function,
    # we may be in the midst of a function, and see internally registers being used, so we'll just
    # skip this validation
    func_ends = list(find_function_ends(func))
    if len(func_ends) > 1:
        logger.trace("aborting because more than one function end was found...")
        return False

    # look for "useless" writes into non-result regs
    try:
        for l in code_flow_iterator(func_ends[0], forward=False):
            logger.trace(f"-> {l.disasm}")

            # regs that we'll treat as result regs once done with this instruction
            new_result_regs = set()

            insn = l.insn

            for op in get_insn_ops_with_condition_flags(insn):
                regs = get_op_regs(op)

                for r in regs:
                    if op.is_write and not op.type.is_displ:
                        # if we're writing into a result reg, it's all good
                        if r in result_regs:
                            continue

                        # if a non-result reg is being written into it's either that or that it's actually a
                        # callee saved reg, and the we're restoring its value here
                        if r in potential_callee_saved_regs and insn.mnem in callee_saved_allowed_mnems:
                            # if it's the latter case -- we'll remember it
                            callee_saved_regs[r] = (l.ea, insn.mnem)
                            logger.trace(f"   marking {r} as callee saved")
                            continue

                        logger.trace(f"   found write into non-result reg {r}")
                        return True
                    elif op.is_read or op.type.is_displ:
                        if r in result_regs:
                            continue

                        # if we got here and won't return True on anything else about this instruction,
                        # it means that this non-result reg is read and is either stored into memory
                        # or affects only-result regs. in both of these cases, we should treat it as
                        # a result reg as well

                        # special treatment for registers who aren't can't be split into parts
                        if r == "NZCV":
                            logger.trace(f"   marking {r} as result reg")
                            new_result_regs.add(r)
                            continue

                        # mark all of the "parts" of this register as result regs
                        logger.trace(f"   marking *{r[1:]} as result regs")
                        new_result_regs.update(register_parts(r))

            result_regs |= new_result_regs

    except FunctionInlinerUnknownFlowException:
        logger.trace("aborting because code flow cannot be followed any longer...")
        return False

    # verify that callee saved regs are actually stored in the beginning
    # if not -- they were really just written to and not restored
    if not callee_saved_regs:
        return False

    logger.trace("finished backwards pass ; starting forward pass")

    try:
        for l in code_flow_iterator(sark.Line(func.start_ea)):
            logger.trace(f"-> {l.disasm}")

            insn = l.insn
            for op in get_insn_ops_with_condition_flags(insn):
                for r in op.regs:
                    if r not in callee_saved_regs:
                        continue

                    restore_ea, restore_mnem = callee_saved_regs[r]
                    store_mnem = callee_saved_allowed_mnems[restore_mnem]

                    # the first "use" of the callee saved reg must be to store it, mnem must match
                    # the restoring mnem, and the ea must be before that of the restoring ea
                    if not op.is_read or not insn.mnem == store_mnem or l.ea > restore_ea:
                        logger.trace(f"   first use of callee saved {r} isn't storing")
                        return True

                    # it was properly stored -> forget about it
                    logger.trace(f"   found store of callee saved {r}")
                    del callee_saved_regs[r]
                    if not callee_saved_regs:
                        return False

    except FunctionInlinerUnknownFlowException:
        logger.trace("aborting because code flow cannot be followed any longer...")

    return False


def is_function_outlined(func, include_inlined=False):
    if include_inlined:
        if func.ea in ClonesStorage().items:
            return True

    # nothing to do here if we have no callers
    if not list(external_callers(func)):
        return False

    # i'm not really sure about whether outlined functions never have prologues, but we'll see
    if is_function_prologue(sark.Line(func.ea)):
        return False

    if is_function_using_uninitialized_regs(func):
        return True

    if is_function_affecting_non_result_regs(func):
        return True

    return False


def find_next_reg_use(line, reg):
    reg_parts = set(register_parts(reg))

    for l in code_flow_iterator(line, abort_on_calls=False, dfs=True):
        for op in l.insn.operands:
            if not op.regs & reg_parts:
                continue
            if op.is_write:
                return None
            else:
                return l


def apply_code_patch(start_ea, end_ea, code, kp_asm=None):
    if kp_asm is None:
        kp_asm = keypatch.Keypatch_Asm()

    size = end_ea - start_ea
    assert len(code) <= size

    if len(code) < size:
        nop = bytes(kp_asm.assemble("NOP", 0)[0])
        nop_slide_size = size - len(code)
        assert nop_slide_size % len(nop) == 0
        code += nop * (nop_slide_size // len(nop))

    assert len(code) == size
    idaapi.patch_bytes(start_ea, code)
    idaapi.plan_range(start_ea, end_ea)


def patch_constant_BRs(kp_asm=None):
    """patches snippets of the form:
                ADR/L     Xn, sub_1337
                NOP/-
                BR/BLR    Xn

        to:
                B/BL      sub_1337
    """
    if kp_asm is None:
        kp_asm = keypatch.Keypatch_Asm()

    count = 0
    retval = True
    for l1, l2, l3 in linegroups(3):
        if idaapi.user_cancelled():
            retval = False
            break

        # check if we're at a constant BR
        try:
            if l1.insn.mnem not in ("ADR", "ADRL"):
                continue

            if l1.insn.mnem == "ADR":
                if l2.insn.mnem != "NOP":
                    continue
            else:  # ADRL spans 8 bytes and hence no NOP
                l3 = l2  # align both cases' line numbers

            if l3.insn.mnem not in ("BR", "BLR"):
                continue
        except sark.exceptions.SarkNoInstruction:
            continue

        target_ea = l1.insn.operands[1].value

        r = l1.insn.operands[0].text
        if r != l3.insn.operands[0].text:
            continue

        logger.debug(f"found constant BR to {target_ea:#x} at {l1.ea:#x}")

        # verify that the register isn't used in the rest of the function
        l = find_next_reg_use(l3.next, r)
        if l is not None:
            logger.debug(f"  constant BR is unpatchable because there's another ref to {r} at {l.ea:#x}")
            continue

        # patch to a standard call
        call_mnem = l3.insn.mnem[:-1]
        asm = f"{call_mnem} #{target_ea:#x}"  # we drop PAC flags
        code = bytes(kp_asm.assemble(asm, l1.ea)[0])
        apply_code_patch(l1.ea, l3.end_ea, code, kp_asm)

        add_comment(l1, f"FunctionInliner: patched from constant BR using {r}")

        logger.debug("  patched")
        count += 1

    logger.info(f"patched {count} constant BRs")
    return retval


def patch_constant_tested_BRs(kp_asm=None):
    """patches snippets of the form:
                ADR/L     Xn, sub_1337
                NOP/-
                CBNZ      Xn, do_call
                B         dont_call
            do_call:
                BR/BLR    Xn
            dont_call:

        to:
                B/BL      sub_1337
    """
    if kp_asm is None:
        kp_asm = keypatch.Keypatch_Asm()

    count = 0
    retval = True
    for l1, l2, l3, l4, l5 in linegroups(5):
        if idaapi.user_cancelled():
            retval = False
            break

        # check if we're at a constant BR
        try:
            if l1.insn.mnem not in ("ADR", "ADRL"):
                continue

            if l1.insn.mnem == "ADR":
                if l2.insn.mnem != "NOP":
                    continue
            else:  # ADRL spans 8 bytes and hence no NOP
                l3, l4, l5 = l2, l3, l4  # align both cases' line numbers

            target_ea = l1.insn.operands[1].value
            r = l1.insn.operands[0].text

            if (l3.insn.mnem != "CBNZ"
               or l3.insn.operands[0].text != r  # noqa: W503
               or l3.insn.operands[1].addr != l5.ea):  # noqa: W503
                continue

            if (l4.insn.mnem != "B"
               or l4.insn.operands[0].addr != l5.end_ea):  # noqa: W503
                continue

            if (l5.insn.mnem not in ("BR", "BLR")
               or l5.insn.operands[0].text != r):  # noqa: W503
                continue
        except sark.exceptions.SarkNoInstruction:
            continue

        logger.debug(f"found constant tested BR to {target_ea:#x} at {l1.ea:#x}")

        try:
            sark.Function(l5.next)
        except sark.exceptions.SarkNoFunction:
            logger.debug(f"  constant tested BR is unpatchable because this is not a function and so"
                         f" we couldn't verify whether there's another ref to {r}")
            continue

        # verify that the register isn't used in the rest of the function
        l = find_next_reg_use(l5.next, r)
        if l is not None:
            logger.debug(f"  constant tested BR is unpatchable because there's another ref to {r} at {l.ea:#x}")
            continue

        # patch to a standard call
        call_mnem = l5.insn.mnem[:-1]
        asm = f"{call_mnem} #{target_ea:#x}"  # we drop PAC flags
        code = bytes(kp_asm.assemble(asm, l1.ea)[0])
        apply_code_patch(l1.ea, l5.end_ea, code, kp_asm)

        add_comment(l1, f"FunctionInliner: patched from constant tested BR using {r}")

        logger.debug("  patched")
        count += 1

    logger.info(f"patched {count} constant tested BRs")
    return retval


def patch_constant_data_BLRs(kp_asm=None):
    """patches snippets of the form:
                NOP/ADRP
                LDR       Xn, =sub_1337
                BLR       Xn

        where the data lives in a const segment

        to:
                BL      sub_1337
    """
    if kp_asm is None:
        kp_asm = keypatch.Keypatch_Asm()

    count = 0
    retval = True
    for l1, l2, l3 in linegroups(3):
        if idaapi.user_cancelled():
            retval = False
            break

        # check if we're at a constant BR
        try:
            if l2.insn.mnem != "LDR":
                continue

            if l1.insn.mnem == "NOP":
                if not l2.insn.operands[1].type.is_mem:
                    continue
            elif l1.insn.mnem == "ADRP":
                if not l2.insn.operands[1].type.is_displ:
                    continue
                if not l2.insn.operands[1].reg == l1.insn.operands[0].reg:
                    continue
            else:
                continue

            r = l2.insn.operands[0].reg

            if l3.insn.mnem != "BLR" or l3.insn.operands[0].reg != r:
                continue
        except sark.exceptions.SarkNoInstruction:
            continue

        # resolve the loaded addr
        drefs_from = set(l2.drefs_from)
        if len(drefs_from) == 1:
            p_target_ea = drefs_from.pop()
        else:  # this may happen with LDR when the target contains another address
            assert len(drefs_from) == 2 and l2.insn.mnem == "LDR"
            xref = [x for x in l2.xrefs_from if x.type.is_read][0]
            p_target_ea = xref.to

        # skip pointers which aren't in __auth_ptr or in const data segments
        p_target_seg_name = sark.Segment(p_target_ea).name
        if p_target_seg_name != "__auth_ptr" and "const" not in p_target_seg_name.lower():
            continue

        target_ea = idaapi.get_qword(p_target_ea)

        logger.debug(f"found constant data BLR to {target_ea:#x} at {l1.ea:#x}")

        # verify that the register isn't used in the rest of the function
        l = find_next_reg_use(l3.next, r)
        if l is not None:
            logger.debug(f"  constant data BLR is unpatchable because there's another ref to {r} at {l.ea:#x}")
            continue

        # patch to a standard call
        asm = f"BL #{target_ea:#x}"  # we drop PAC flags
        code = bytes(kp_asm.assemble(asm, l1.ea)[0])
        apply_code_patch(l1.ea, l3.end_ea, code, kp_asm)

        add_comment(l1, f"FunctionInliner: patched from constant data BLR using {r}")

        logger.debug("  patched")
        count += 1

    logger.info(f"patched {count} constant data BLRs")
    return retval


# PLUGIN STUFF


class FunctionInlinerActionBase(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    @property
    def name(self):
        return f"{self.plugin.wanted_name}:{self.__class__.__name__}"

    @property
    def label(self):
        return "Inline function under cursor"

    @property
    def shortcut(self):
        return None

    @property
    def tooltip(self):
        return None

    @property
    def icon(self):
        return idaapi.get_action_icon("MakeFunction")[1]

    @property
    def flags(self):
        return 0

    @property
    def path(self):
        return f"Edit/Plugins/{self.plugin.wanted_name}/"

    def register(self):
        desc = idaapi.action_desc_t(
            self.name,
            self.label,
            self,
            self.shortcut,
            self.tooltip,
            self.icon,
        )
        idaapi.register_action(desc)

    def unregister(self):
        idaapi.unregister_action(self.name)

    def activate(self, ctx):
        raise NotImplementedError()

    def update(self, ctx):
        raise NotImplementedError()


class FunctionInlinerInlineAction(FunctionInlinerActionBase):
    @property
    def label(self):
        return "Inline function"

    def activate(self, ctx):
        func = get_function_under_cursor()
        inline_function(func)
        return 1

    def update(self, ctx):
        f = get_function_under_cursor()
        if f and list(external_callers(f)):
            return idaapi.AST_ENABLE
        else:
            return idaapi.AST_DISABLE


class FunctionInlinerUndoInlineAction(FunctionInlinerActionBase):
    @property
    def label(self):
        return "Undo function inlining"

    def activate(self, ctx):
        outlined_func = get_inlined_function_under_cursor()
        undo_inline_function(outlined_func)
        return 1

    def update(self, ctx):
        if get_inlined_function_under_cursor():
            return idaapi.AST_ENABLE
        else:
            return idaapi.AST_DISABLE


class FunctionInlinerInlineAllAction(FunctionInlinerActionBase):
    @property
    def label(self):
        return "Inline all outlined functions"

    def activate(self, ctx):
        if not preprocess_idb():
            return 1
        if not inline_all_functions():
            return 1
        postprocess_idb()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class FunctionInlinerPatchConstantBLRs(FunctionInlinerActionBase):
    @property
    def label(self):
        return "Patch constant register-based calls to regular calls"

    def activate(self, ctx):
        with wait_box("patching constant BRs..."):
            if not patch_constant_BRs():
                return 1
            if not patch_constant_tested_BRs():
                return 1
            if not patch_constant_data_BLRs():
                return 1
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class FunctionInlinerHooks(idaapi.UI_Hooks):
    def __init__(self, ctx_actions, menu_actions):
        super().__init__()

        self.ctx_actions = ctx_actions
        self.menu_actions = menu_actions

    def ready_to_run(self):
        for action in self.menu_actions:
            idaapi.attach_action_to_menu(action.path, action.name, idaapi.SETMENU_APP)

    def finish_populating_tform_popup(self, form, popup):
        if idaapi.get_tform_type(form) in (idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE):
            idaapi.attach_action_to_popup(form, popup, "-", None, idaapi.SETMENU_FIRST)
            for action in reversed(self.ctx_actions):
                idaapi.attach_action_to_popup(form, popup, action.name, None, idaapi.SETMENU_FIRST)


class FunctionInlinerPlugin(idaapi.plugin_t):
    version = idaapi.IDP_INTERFACE_VERSION
    flags = idaapi.PLUGIN_MOD | idaapi.PLUGIN_HIDE

    comment = "inlines functions that were outlined"
    help = ""
    wanted_name = "FunctionInliner"
    wanted_hotkey = ""

    ctx_actions_types = (FunctionInlinerInlineAction, FunctionInlinerUndoInlineAction)
    menu_actions_types = (FunctionInlinerPatchConstantBLRs, FunctionInlinerInlineAllAction)

    @staticmethod
    def init_logging():
        logger_formatter = logging.Formatter(fmt="{name}.{levelname:<5s}: {message}", style="{")

        class TqdmHandler(logging.StreamHandler):
            def emit(self, record):
                msg = self.format(record)
                tqdm.tqdm.write(msg)

        logger_hdlr = TqdmHandler()
        logger_hdlr.setFormatter(logger_formatter)

        logger.addHandler(logger_hdlr)

        if TRACE:
            logger.setLevel(logging.TRACE)
        else:
            logger.setLevel(logging.INFO)

    def is_compatible(self):
        info = idaapi.get_inf_structure()
        return info.procName == "ARM" and info.is_64bit()

    def init(self):
        super().__init__()

        FunctionInlinerPlugin.init_logging()

        self.ctx_actions = []
        self.menu_actions = []
        self.hooks = None

        if not self.is_compatible():
            logger.error("IDB deemed unsuitable (not an ARM64 binary). Skipping...")
            return idaapi.PLUGIN_SKIP

        for t in FunctionInlinerPlugin.ctx_actions_types:
            a = t(self)
            a.register()
            self.ctx_actions.append(a)

        for t in FunctionInlinerPlugin.menu_actions_types:
            a = t(self)
            a.register()
            self.menu_actions.append(a)

        self.hooks = FunctionInlinerHooks(self.ctx_actions, self.menu_actions)
        self.hooks.hook()

        logger.info("initialized successfully")

        return idaapi.PLUGIN_KEEP

    def term(self):
        if self.hooks:
            self.hooks.unhook()

        for a in self.ctx_actions:
            a.unregister()

        for a in self.menu_actions:
            a.unregister()

    def run(self, arg=0):
        pass


def PLUGIN_ENTRY():
    return FunctionInlinerPlugin()
