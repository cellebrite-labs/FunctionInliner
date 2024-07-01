# FunctionInliner

FunctionInliner is an IDA plugin that can be used to ease the reversing of binaries that have been
space-optimized with function outlining (e.g. `clang --moutline`).

Our plugin works by creating a clone of the outlined function per each of its xref callers, and
linking it to the caller directly by replacing the BL to with a regular branch to the clone and the
RET of the clone with a branch back to the caller (thus adding the clone as a function chunk of its
caller).

In case the an outlined function has been succesfully inlined into all of its callers, it'll be
renamed to have the `inlined_` prefix, to make it easy to identify in functions/xrefs listing.

The plugin supports both manually choosing functions to inline from their context menu, and
heuristically identifying all outlined functions and inlining them.

## Why?

Code with outlined functions is a pain to reverse because the outlined functions usually use
registers and memory that is local to their *caller* (i.e. they don't conform to the ABI). Therefore
you don't have the entire context when reversing the caller and have to jump back and forth into
those outlined parts to follow what's going on.

Moreover, reversing code with outlined functions using Hex Rays simply doesn't work since Hex Rays
assumes that functions conform to the ABI in order to do its magic. Moreover, if you'll try to jump
into the outlined function in Hex Rays you'll often see them as empty because of that.

## Example

As an example we used gzip 1.3.5 which is a single source file that was easy to work with, and we
looked at the beginning of a single function from it (`bi_windup`):

![](test/test.png)

On the left, you see the function compiled with `-O3` and in the middle you see it compiled with
`-O3 -moutline`. Calls to outlined functions were highlighted (obviously, these wouldn't have stood
out from other calls in case symbols have been stripped).

We've also marked some screwups in Hex Rays' decompilation that were caused by these outlined
functions not conforming to the ABI.

On the right, you see the same function after our whole-IDB analysis has been applied. You can see
that most outlined functions have been automatically inlined, and all decompilation screwups have
been resolved.

To be exact, in this file our whole-IDB analysis found and automayically inlined 130 out of 165
outlined functions, with no false positives. The rest of the outlined functions can be easily
inlined from their context menu in case they're manually identified later.

Specifically in this example, you can also see that `OUTLINED_FUNCTION_13` (which was not
automatically inlined) is a simple wrapper to `write` which specifies `nbytes = 0x4000`. In this
case we could never determine whether this was an original wrapper function or an outlined function
that we should inline.

## Installation

1. Install the dependencies listed in `requirements.txt` where IDA can import them. For example
   using `/path/to/python3/used/by/ida -m pip install -r requirements.txt`.
2. Install [keypatch](https://github.com/keystone-engine/keypatch).
3. Clone this repository and symlink `~/.idapro/plugins/functioninliner.py` to `functioninliner.py`
   in the cloned repo.

## Usage TL;DR

From the menu select `Edit -> Plugins -> FunctionInliner -> Patch constant register-based calls to
regular calls` and then `Edit -> Plugin -> FunctionInliner -> Inline all outlined functions` in
order to try and do everything we can to make the IDB more readable.

## Per-function usage

Note: all of the context menus described below work both in IDA views and in Psuedocode views.

### Inlining outlined functions

Right-click on a `BL` to an outlined function, or on the beginning of an outlined function and
choose `Inline function` (or use the keyboard shortcut `Meta-P`, i.e. `Cmd/WinKey-P`).

Note that the cloning logic does not support functions which consist of multiple function
chunks. For such cases, you should dechunk the function manually, or have it done automatically by
running our whole-IDB processing.

### Undoing inlining of outlined functions

Right-click on a `B` to the cloned code that was originally outlined, on the begining of the cloned
code, or on the beginning of the original outlined function and choose `Undo function inlining`

## Whole-IDB usage

The plugin also supports working on the entire IDB and inlining *every* function that is identified
as an outlined function. See the `Principals of operation` section for the heuristics used to
identify these.

### Inlining all outlined functions

From the menu select `Edit -> Plugins -> FunctionInliner -> Inline all outlined functions` in order
to scan all of the functions in the binary and inline those who are identified as outlined.

Note that we first do some preprocessing on the entire IDB in order to fix various situations that
may have occured from IDA auto-analyzing the IDB without taking outlined functions into
consideration.

### Patching constant register-based calls

In some cases the compiler and linker generate register-based calls for constant addresses (and not
regular calls). IDA obviously doesn't generate call xrefs in these cases (but data xrefs) and so our
inlining logic cannot patch these calls.

From the menu select `Edit -> Plugins -> FunctionInliner -> Patch constant register-based calls to
regular calls` in order to scan all of the IDB for these patterns and patch them to regular calls.

Since this behaviour is actively patching the IDB we kept it as a separate (optional) action, and do
not do this as part of the `Inline all outlined functions` preprocessing logic.

## Principals of operation

### What preprocessing is done prior to inlining all outlined functions

Our preprocessing is comprised of a number of steps:
1. Exploration steps are repeated until there's nothing new to be done:
   1. We create functions at xref targets that IDA didn't make a function out of.
   1. We identify NORET functions that IDA didn't identify as such.
2. Preprocessing steps are done afterward the exploration:
   1. We dechunks all of the functions in the binary (split each chunk into a separate function).
      This helps us identify later on which chunks were outlined and which are "real" functions.
      Plus, our cloning logic doesn't support chunked functions.
   2. We split functions that are placed right before another function they tail-call into, and were
      treated by IDA as one whole function.
   3. We split adjacent functions that were treated by IDA as one whole function.

### How cloning is done

For each xref to the outlined function, we create a new segment named
`inlined_0x{func_ea:x}_for_0x{src_ea:x}` and clone the function there.

When cloning, we in fact have to translate some of the opcodes on the way -- if an opcode has
relative data or code xrefs we need to fix them to work from the new location. We also may have to
fix relative xrefs inside the cloned code because our translation may move stuff around in the clone
as well.

We then replace the original `BL` to the outlined function with a `B` to the cloned code, and
replace the `RET` in the end of the outlined function with a `B` back to the caller.

There are of course edge cases when the outlined function tail-calls some other function, or when
the outlined function is tail-called by its caller, which should be handled.

We also take care to find a spot for the cloned code segment which will be close enough to the
caller and to outgoing xrefs from the clone in order to use regular branches back and forth.

### How outlined functions are identified

Currently we use a few heuristics to identify outlined functions.

There may be false-negatives (i.e. we may miss some outlined functions) but we expect their count to
be pretty low and they can always be inlined manually when encountered.

Also, in case there will be any false-positives (i.e. we'll identify some real functions as outlined
and inline them into their callers) the effect shouldn't be that bad for RE and can also be undone
manually.

The heuristics we use are the following:
1. ~~We expect outlined functions to have more than one caller (otherwise it wouldn't have been useful
   to outline them)~~ for some reason this doesn't hold in real cases, so we've dropped this
   heuristic.
2. We expect all outlined functions not to have a prologue (not really sure about that, but it makes
   sense). This is more of an optimization for us, in order not to statically analyze *every*
   function in the IDB.
3. We expect some outlined functions not to conform to the ABI and to make use of non-argument
   registers that were not initialized internally.
4. We expect some outlined functions not to conform to the ABI and to leave side-effects on
   non-result registers (that are not propagated to any result register or stored in memory).
5. The last two heuristics also hold for condition flags and not registers (i.e. if the function is
   using uninitializing/setting unused condition flags).

## Future improvements

There are some cases of outlined functions that we currently don't auto detect with our heuristics:
1. Some outlined functions leave side-effects on higher result registers but do not set all of the
   lower ones, so it's obvious that they're not just returning a structure by value.
2. Consider removing the heuristic about outlined functions not having prologues, since we've seen
   cases of outlined prologues.

There are some cases which our cloning logic doesn't support:
1. Some uses of conditional opcodes (e.g. when the call to the outlined function is a conditional
   tail-call).

Some other stuff:
1. When running our heuristics, we currently stop analyzing a function if we encounter a BL or a
   tail-call in it, because that may lead to another outlined function. The proper handling should
   probably be to analyze and inline all functions in order of a topological sort based on call
   targets (i.e. first analyze and inline functions which don't call anything, then those who call
   already analyzed functions, and so on).
2. When running our heuristics, we usually stop analyzing a function if we encounter more than one
   basic block. We could theoretically continue analyzing recursively in each of the branches.

## Limitations

The plugin currently works only on ARM64 binaries that conform to
[the ABI](https://developer.arm.com/documentation/ihi0055/d?lang=en).

## Fixing corrupted state

If for any reason (e.g. IDA crashed in the middle of function inlining) the IDB has gotten into
corrupted state with regards to FunctionInliner, where for example:
1. You have deleted but not disabled addresses that were once inlined clones.
2. You have inlined clones with unpatched source calls.
3. You have patched source calls with missing clones.
4. FunctionInliner thinks it has already inlined (or undid inlining of) something which it hasn't.

You should run the `fix_state.py` script in the context of the corrupted IDB.

In our testing, this happened once after months of heavy usage, and we suspect another conflicting
plugin to cause this, so we didn't bother integrating the fixing logic into the plugin.

## Meta

Authored by Tomer Harpaz of Cellebrite Security Research Labs.
Developed and tested for IDA 7.6 on macOS with Python 3.7.9.
Also tested on IDA up to 8.4
