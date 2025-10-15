import ida_bytes
import ida_hexrays
import idaapi
from ida_hexrays import carg_t, carglist_t, cexpr_t, cfunc_t, cfuncptr_t, lvar_t, number_format_t, var_ref_t
from ida_typeinf import tinfo_t

from idahelper import memory, tif
from idahelper.ast import lvars


def get_call_name(call_expr: cexpr_t) -> str | None:
    """Get the name of the called function from a call expression."""
    assert call_expr.op == ida_hexrays.cot_call, "Expected a call expression"
    called_func: cexpr_t = call_expr.x
    if called_func.op == ida_hexrays.cot_helper:
        return called_func.helper
    elif called_func.op == ida_hexrays.cot_obj:
        return memory.name_from_ea(called_func.obj_ea)

    return None


def strip_casts(expr: cexpr_t) -> cexpr_t:
    """Strip casts from the expression."""
    while expr.op == ida_hexrays.cot_cast:
        expr = expr.x
    return expr


def from_cast(expr: cexpr_t, typ: tinfo_t) -> cexpr_t:
    """Create a cast expression from an existing expression and a type."""
    cast_expr = cexpr_t()
    cast_expr.op = ida_hexrays.cot_cast
    cast_expr.x = cexpr_t(expr)
    cast_expr.type = typ
    return cast_expr


def from_var(var: var_ref_t) -> cexpr_t:
    """Create a cexpr_t from a var_ref_t."""
    var_t: lvar_t = var.getv()
    var_expr = cexpr_t()
    var_expr.op = ida_hexrays.cot_var
    var_expr.v = var
    var_expr.type = var_t.type()
    return var_expr


def from_lvar_index(lvar_index: int, func: cfuncptr_t) -> cexpr_t:
    """Create a cexpr_t from a lvar index in func."""
    var_ref = var_ref_t()
    var_ref.mba = func.mba
    var_ref.idx = lvar_index

    return from_var(var_ref)


def from_var_name(name: str, func: cfuncptr_t) -> cexpr_t:
    """Create a cexpr_t from a variable name and the container function."""
    return from_lvar_index(lvars.get_index_by_name(func.get_lvars(), name), func)


def from_const_value(
    x: int, cur_func: cfuncptr_t | cfunc_t | None = None, ea: int = idaapi.BADADDR, is_hex: bool = False
) -> cexpr_t:
    """Create a cexpr_t from a constant value."""
    num = ida_hexrays.make_num(x, cur_func, ea)
    if is_hex:
        nf: number_format_t = num.n.nf
        nf.flags = ida_bytes.hex_flag()
        nf.flags32 = nf.flags & 0xFF_FF_FF_FF
    return num


def from_binary_op(lhs: cexpr_t, rhs: cexpr_t, op: int, typ: tinfo_t, ea: int = idaapi.BADADDR) -> cexpr_t:
    """Create the binary operation expression `lhs op rhs`."""
    bin_expr = cexpr_t()
    bin_expr.ea = ea
    bin_expr.type = typ
    bin_expr.op = op
    bin_expr.x = lhs
    bin_expr.y = rhs
    return bin_expr


def from_assignment(lhs: cexpr_t, rhs: cexpr_t) -> cexpr_t:
    """Create an assignment expression from `lhs` and `rhs`."""
    assign_expr = cexpr_t()
    assign_expr.op = ida_hexrays.cot_asg
    assign_expr.x = lhs
    assign_expr.y = rhs
    assign_expr.type = lhs.type
    return assign_expr


def from_string(s: str, ea: int = idaapi.BADADDR) -> cexpr_t:
    """Create a string expression from a const string."""
    e = cexpr_t()
    e.ea = ea
    e.op = ida_hexrays.cot_str
    e.type = tif.from_c_type("char*")
    e.string = s
    return e


def call_helper_from_sig(name: str, ret_type: tinfo_t, args: list[cexpr_t | carg_t]) -> cexpr_t:
    """Create a call expression from a name, arguments and return type"""
    return ida_hexrays.call_helper(ret_type, arglist_from_expr_arr(*args), name)


def from_call_and_args(call: cexpr_t, *args: cexpr_t | carg_t) -> cexpr_t:
    """Create a call expression from a call and arguments."""
    call_expr = cexpr_t()
    call_expr.op = ida_hexrays.cot_call
    call_expr.x = call
    call_expr.a = arglist_from_expr_arr(*args)
    return call_expr


def arglist_from_expr_arr(*args: cexpr_t | carg_t) -> carglist_t:
    """Convert a list of cexpr_t to a carglist_t."""
    arglist = carglist_t()
    for arg in args:
        if arg is None:
            print("[Warning]: argument is None")
            continue

        arglist.push_back(carg_from_expr(arg))
    return arglist


def carg_from_expr(expr: cexpr_t) -> carg_t:
    """Convert a cexpr_t to a carg_t."""
    if isinstance(expr, carg_t):
        return expr
    else:
        carg = carg_t()
        carg.assign(expr)
    return carg
