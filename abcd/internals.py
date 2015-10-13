# Copyright (c) 2015 The MITRE Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

from common import ABCdCommon

class Namespace(object):
    def __init__(self, kind, name):
        self._kind = kind
        self._name = name

    @property
    def kind(self):
        """Namespace kind."""
        return self._kind

    @property
    def name(self):
        """Index of namespace name."""
        return self._name

class Multiname_QName(object):
    def __init__(self, ns, name):
        self._ns = ns
        self._name = name

    @property
    def ns(self):
        """Index into namespace list."""
        return self._ns

    @property
    def name(self):
        """Name index."""
        return self._name

class Multiname_RTQName(object):
    def __init__(self, name):
        self._name = name

    @property
    def name(self):
        """Name index."""
        return self._name

class Multiname_RTQNameL(object):
    def __init__(self):
        pass

class Multiname_Multiname(object):
    def __init__(self, name, ns_set):
        if ns_set == 0:
            raise ABCdBadValue("Invalid ns_set", ns_set)
        self._name = name
        self._ns_set = ns_set

    @property
    def name(self):
        """Name index."""
        return self._name

    @property
    def ns_set(self):
        """Namespace Set index."""
        return self._ns_set

class Multiname_MultinameL(object):
    def __init__(self, ns_set):
        if ns_set == 0:
            raise ABCdBadValue("Invalid ns_set", ns_set)
        self._ns_set = ns_set

    @property
    def ns_set(self):
        """Namespace Set index."""
        return self._ns_set

# Where is this documented?
class Multiname_Typename(object):
    def __init__(self, name, params):
        self._name = name
        self._params = params

    @property
    def name(self):
        """Name index."""
        return self._name

    @property
    def params(self):
        """List of parameter indexes."""
        return self._params

class Method(ABCdCommon):
    def __init__(self,
                 return_type,
                 param_types,
                 name,
                 flags,
                 options,
                 param_names,
                 parser):
        self._return_type = return_type
        self._param_types = param_types
        self._name = name
        self._flags = flags
        self._options = options
        self._param_names = param_names
        self._parser = parser

    @property
    def return_type(self):
        """Index of return type."""
        return self._return_type

    @property
    def param_types(self):
        """List of indexes of parameter types."""
        return self._param_types

    @property
    def name(self):
        """Index of method name."""
        return self._name

    @property
    def flags(self):
        """Method flags (bitmask)."""
        return self._flags

    @property
    def options(self):
        """List of Option objects."""
        return self._options

    @property
    def param_names(self):
        """List of indexes of parameter names."""
        return self._param_names

    def __str__(self):
        # XXX: Deal with parameter names and optionals...
        if self.return_type == 0:
            return_type = "*"
        else:
            return_type = self._parser.resolve_multiname(self.return_type)

        if self.name == 0:
            method_name = "NO_NAME"
        else:
            method_name = self._parser.strings[self.name]

        pt = []
        for param_type in self.param_types:
            if param_type == 0:
                pt.append("*")
            else:
                pt.append(self._parser.resolve_multiname(param_type))
        return "%s %s(%s)" % (return_type, method_name, ', '.join(pt))

class Metadata(object):
    def __init__(self, name, items):
        self._name = name
        self._items = items

    @property
    def name(self):
        """Index of metadata name."""
        return self._name

    @property
    def items(self):
        """List of Metadata_Item objects."""
        return self._items

class Metadata_Item(object):
    def __init__(self, key, value):
        self._key = key
        self._value = value

    @property
    def key(self):
        """Key for metadata item."""
        return self._key

    @property
    def value(self):
        """Value for metadata item."""
        return self._value

class Option(object):
    def __init__(self, val, kind):
        self._val = val
        self._kind = kind

    @property
    def val(self):
        """Optional parameter value."""
        return self._val

    @property
    def kind(self):
        """Optional parameter kind."""
        return self._kind

class Instance(object):
    def __init__(self,
                 name,
                 super_name,
                 flags,
                 protected_ns,
                 interfaces,
                 iinit,
                 traits):
        self._name = name
        self._super_name = super_name
        self._flags = flags
        self._protected_ns = protected_ns
        self._interfaces = interfaces
        self._iinit = iinit
        self._traits = traits

    @property
    def name(self):
        """Instance name index."""
        return self._name

    @property
    def super_name(self):
        """Super name index."""
        return self._super_name

    @property
    def flags(self):
        """Instance flags (bitmask)."""
        return self._flags

    @property
    def protected_ns(self):
        """Protected namespace index."""
        return self._protected_ns

    @property
    def interfaces(self):
        """Array of interface indexes."""
        return self._interfaces

    @property
    def iinit(self):
        """Instance initialization index."""
        return self._iinit

    @property
    def traits(self):
        """List of traits."""
        return self._traits

class Class(object):
    def __init__(self, cinit, traits):
        self._cinit = cinit
        self._traits = traits

    @property
    def cinit(self):
        """Class initialization index"""
        return self._cinit

    @property
    def traits(self):
        """List of traits."""
        return self._traits

class Script(object):
    def __init__(self, init, traits):
        self._init = init
        self._traits = traits

    @property
    def init(self):
        """Script initialization index."""
        return self._init

    @property
    def traits(self):
        """List of traits."""
        return self._traits

class OpCode(object):
    def __init__(self, opcode, operands, name):
        self._opcode = opcode
        self._operands = operands
        self._name = name

    @property
    def opcode(self):
        """Opcode byte."""
        return self._opcode

    @property
    def operands(self):
        """List of operands."""
        return self._operands

    @property
    def name(self):
        """Instruction name."""
        return self._name

class MethodBody(ABCdCommon):
    def __init__(self,
                 method,
                 max_stack,
                 local_count,
                 init_scope_depth,
                 max_scope_depth,
                 code,
                 exceptions,
                 traits,
                 parser):
        self._method = method
        self._max_stack = max_stack
        self._local_count = local_count
        self._init_scope_depth = init_scope_depth
        self._max_scope_depth = max_scope_depth
        self._code = code
        self._exceptions = exceptions
        self._traits = traits
        self._parser = parser

        # The "ActionScript Virtual Machine 2 (AVM2) Overview" documentation
        # published by Adobe was last updated in 2007 and does not contain
        # all instructions. Looks like https://github.com/adobe-flash/avmplus
        # has a lot of the missing ones.
        self._OPCODES = {
            # These are the ones not mentioned in official documentation.
            # These are prefixed with 'OP_' to visually stand out.
            0x01: {'name': 'OP_bkpt', 'operands': []},
            0x22: {'name': 'OP_pushconstant', 'operands': []},
            0x35: {'name': 'OP_li8', 'operands': []},
            0x36: {'name': 'OP_li16', 'operands': []},
            0x37: {'name': 'OP_li32', 'operands': []},
            0x38: {'name': 'OP_lf32', 'operands': []},
            0x39: {'name': 'OP_lf64', 'operands': []},
            0x3A: {'name': 'OP_si8', 'operands': []},
            0x3B: {'name': 'OP_si16', 'operands': []},
            0x3C: {'name': 'OP_si32', 'operands': []},
            0x3D: {'name': 'OP_sf32', 'operands': []},
            0x3E: {'name': 'OP_sf64', 'operands': []},
            0x4B: {'name': 'OP_callsuperid', 'operands': []},
            0x4D: {'name': 'OP_callinterface', 'operands': []},
            0x50: {'name': 'OP_sxi1', 'operands': []},
            0x51: {'name': 'OP_sxi8', 'operands': []},
            0x52: {'name': 'OP_sxi16', 'operands': []},
            0x53: {'name': 'OP_applytype', 'operands': [self._readU30]},
            0x5F: {'name': 'OP_finddef', 'operands': [self._readU30]},
            0x67: {'name': 'OP_getouterscope', 'operands': []},
            0x6B: {'name': 'OP_deletepropertylate', 'operands': []},
            0x81: {'name': 'OP_coerce_b', 'operands': []},
            0x83: {'name': 'OP_coerce_i', 'operands': []},
            0x84: {'name': 'OP_coerce_d', 'operands': []},
            0x84: {'name': 'OP_coerce_d', 'operands': []},
            0x88: {'name': 'OP_coerce_u', 'operands': []},
            0x89: {'name': 'OP_coerce_o', 'operands': []},
            0x9A: {'name': 'OP_concat', 'operands': []},
            0x9B: {'name': 'OP_add_d', 'operands': []},
            0xF2: {'name': 'OP_bkptline', 'operands': [self._readU30]},
            0xF3: {'name': 'OP_timestamp', 'operands': []},
            # And now with the documented ones...
            0xA0: {'name': 'add', 'operands': []},
            0xC5: {'name': 'add_i', 'operands': []},
            0x86: {'name': 'astype', 'operands': []},
            0x87: {'name': 'astypelate', 'operands': []},
            0xA8: {'name': 'bitand', 'operands': []},
            0x97: {'name': 'bitnot', 'operands': []},
            0xA9: {'name': 'bitor', 'operands': []},
            0xAA: {'name': 'bitxor', 'operands': []},
            0x41: {'name': 'call', 'operands': [self._readU30]},
            0x43: {'name': 'callmethod', 'operands': [self._readU30,
                                                      self._readU30]},
            0x46: {'name': 'callproperty',
                   'operands': [self._readU30, self._readU30],
                   'handler': self._operands_multiname_and_arg},
            0x4C: {'name': 'callproplex',
                   'operands': [self._readU30, self._readU30],
                   'handler': self._operands_multiname_and_arg},
            0x4F: {'name': 'callpropvoid',
                   'operands': [self._readU30, self._readU30],
                   'handler': self._operands_multiname_and_arg},
            0x44: {'name': 'callstatic',
                   'operands': [self._readU30, self._readU30],
                   'handler': self._operands_method_info_and_arg},
            0x45: {'name': 'callsuper',
                   'operands': [self._readU30, self._readU30],
                   'handler': self._operands_multiname_and_arg},
            0x4E: {'name': 'callsupervoid',
                   'operands': [self._readU30, self._readU30],
                   'handler': self._operands_multiname_and_arg},
            0x78: {'name': 'checkfilter', 'operands': []},
            0x80: {'name': 'coerce',
                   'operands': [self._readU30],
                   'handler': self._operands_multiname},
            0x82: {'name': 'coerce_a', 'operands': []},
            0x85: {'name': 'coerce_s', 'operands': []},
            0x42: {'name': 'construct', 'operands': [self._readU30]},
            0x4A: {'name': 'constructprop',
                   'operands': [self._readU30, self._readU30],
                   'handler': self._operands_multiname_and_arg},
            0x49: {'name': 'constructsuper', 'operands': [self._readU30]},
            0x76: {'name': 'convert_b', 'operands': []},
            0x73: {'name': 'convert_i', 'operands': []},
            0x75: {'name': 'convert_d', 'operands': []},
            0x77: {'name': 'convert_o', 'operands': []},
            0x74: {'name': 'convert_u', 'operands': []},
            0x70: {'name': 'convert_s', 'operands': []},
            # XXX: Add a handler for this.
            0xEF: {'name': 'debug', 'operands': [self._readU8,
                                                 self._readU30,
                                                 self._readU8,
                                                 self._readU30]},
            0xF1: {'name': 'debugfile',
                   'operands': [self._readU30],
                   'handler': self._operands_string},
            0xF0: {'name': 'debugline', 'operands': [self._readU30]},
            0x94: {'name': 'declocal', 'operands': [self._readU30]},
            0xC3: {'name': 'declocal_i', 'operands': [self._readU30]},
            0x93: {'name': 'decrement', 'operands': []},
            0xC1: {'name': 'decrement_i', 'operands': []},
            0x6A: {'name': 'deleteproperty',
                   'operands': [self._readU30],
                   'handler': self._operands_multiname},
            0xA3: {'name': 'divide', 'operands': []},
            0x2A: {'name': 'dup', 'operands': []},
            0x06: {'name': 'dxns',
                   'operands': [self._readU30],
                   'handler': self._operands_string},
            0x07: {'name': 'dxnslate', 'operands': []},
            0xAB: {'name': 'equals', 'operands': []},
            0x72: {'name': 'esc_xattr', 'operands': []},
            0x71: {'name': 'esc_xelem', 'operands': []},
            0x5E: {'name': 'findproperty',
                   'operands': [self._readU30],
                   'handler': self._operands_multiname},
            0x5D: {'name': 'findpropstrict',
                   'operands': [self._readU30],
                   'handler': self._operands_multiname},
            0x59: {'name': 'getdescendants',
                   'operands': [self._readU30],
                   'handler': self._operands_multiname},
            0x64: {'name': 'getglobalscope', 'operands': []},
            0x6E: {'name': 'getglobalslot', 'operands': [self._readU30]},
            0x60: {'name': 'getlex',
                   'operands': [self._readU30],
                   'handler': self._operands_multiname},
            0x62: {'name': 'getlocal', 'operands': [self._readU30]},
            0xD0: {'name': 'getlocal_0', 'operands': []},
            0xD1: {'name': 'getlocal_1', 'operands': []},
            0xD2: {'name': 'getlocal_2', 'operands': []},
            0xD3: {'name': 'getlocal_3', 'operands': []},
            0x66: {'name': 'getproperty',
                   'operands': [self._readU30],
                   'handler': self._operands_multiname},
            0x65: {'name': 'getscopeobject', 'operands': [self._readU8]},
            0x6C: {'name': 'getslot', 'operands': [self._readU30]},
            0x04: {'name': 'getsuper',
                   'operands': [self._readU30],
                   'handler': self._operands_multiname},
            # Docs list 0xAF twice... :(
            # 0xAF is greaterthan, 0xB0 is greaterequals.
            0xAF: {'name': 'greaterthan', 'operands': []},
            0xB0: {'name': 'greaterequals', 'operands': []},
            0x1F: {'name': 'hasnext', 'operands': []},
            0x32: {'name': 'hasnext2', 'operands': [self._readU30,
                                                    self._readU30]},
            0x13: {'name': 'ifeq', 'operands': [self._readS24]},
            0x12: {'name': 'iffalse', 'operands': [self._readS24]},
            0x18: {'name': 'ifge', 'operands': [self._readS24]},
            0x17: {'name': 'ifgt', 'operands': [self._readS24]},
            0x16: {'name': 'ifle', 'operands': [self._readS24]},
            0x15: {'name': 'iflt', 'operands': [self._readS24]},
            0x0F: {'name': 'ifnge', 'operands': [self._readS24]},
            0x0E: {'name': 'ifngt', 'operands': [self._readS24]},
            0x0D: {'name': 'ifnle', 'operands': [self._readS24]},
            0x0C: {'name': 'ifnlt', 'operands': [self._readS24]},
            0x14: {'name': 'ifne', 'operands': [self._readS24]},
            0x19: {'name': 'ifstricteq', 'operands': [self._readS24]},
            0x1A: {'name': 'ifstrictne', 'operands': [self._readS24]},
            0x11: {'name': 'iftrue', 'operands': [self._readS24]},
            0xB4: {'name': 'in', 'operands': []},
            0x92: {'name': 'inclocal', 'operands': [self._readU30]},
            0xC2: {'name': 'inclocal_i', 'operands': [self._readU30]},
            0x91: {'name': 'increment', 'operands': []},
            0xC0: {'name': 'increment_i', 'operands': []},
            0x68: {'name': 'initproperty',
                   'operands': [self._readU30],
                   'handler': self._operands_multiname},
            0xB1: {'name': 'instanceof', 'operands': []},
            0xB2: {'name': 'istype',
                   'operands': [self._readU30],
                   'handler': self._operands_multiname},
            0xB3: {'name': 'istypelate', 'operands': []},
            0x10: {'name': 'jump', 'operands': [self._readS24]},
            0x08: {'name': 'kill', 'operands': [self._readU30]},
            0x09: {'name': 'label', 'operands': []},
            0xAE: {'name': 'lessequals', 'operands': []},
            0xAD: {'name': 'lessthan', 'operands': []},
            0x34: {'name': 'pushdnan', 'operands': []},
            # Variable length operands! :(
            # default_offset, case_count, case_offsets...
            0x1B: {'name': 'lookupswitch', 'operands': [self._readS24,
                                                        self._readU30]},
            0xA5: {'name': 'lshift', 'operands': []},
            0xA4: {'name': 'modulo', 'operands': []},
            0xA2: {'name': 'multiply', 'operands': []},
            0xC7: {'name': 'multiply_i', 'operands': []},
            0x90: {'name': 'negate', 'operands': []},
            0xC4: {'name': 'negate_i', 'operands': []},
            0x57: {'name': 'newactivation', 'operands': []},
            0x56: {'name': 'newarray', 'operands': [self._readU30]},
            0x5A: {'name': 'newcatch',
                   'operands': [self._readU30],
                   'handler': self._operands_exception},
            # XXX: Handle operands for newclass...
            0x58: {'name': 'newclass', 'operands': [self._readU30]},
            0x40: {'name': 'newfunction',
                   'operands': [self._readU30],
                   'handler': self._operands_method_info},
            0x55: {'name': 'newobject', 'operands': [self._readU30]},
            0x1E: {'name': 'nextname', 'operands': []},
            0x23: {'name': 'nextvalue', 'operands': []},
            0x02: {'name': 'nop', 'operands': []},
            0x96: {'name': 'not', 'operands': []},
            0x29: {'name': 'pop', 'operands': []},
            0x1D: {'name': 'popscope', 'operands': []},
            0x24: {'name': 'pushbyte', 'operands': [self._readU8]},
            0x2F: {'name': 'pushdouble',
                   'operands': [self._readU30],
                   'handler': self._operands_double},
            0x27: {'name': 'pushfalse', 'operands': []},
            0x2D: {'name': 'pushint',
                   'operands': [self._readU30],
                   'handler': self._operands_int},
            0x31: {'name': 'pushnamespace',
                   'operands': [self._readU30],
                   'handler': self._operands_namespace},
            0x28: {'name': 'pushnan', 'operands': []},
            0x20: {'name': 'pushnull', 'operands': []},
            0x30: {'name': 'pushscope', 'operands': []},
            0x25: {'name': 'pushshort', 'operands': [self._readU30]},
            0x2C: {'name': 'pushstring',
                   'operands': [self._readU30],
                   'handler': self._operands_string},
            0x26: {'name': 'pushtrue', 'operands': []},
            0x2E: {'name': 'pushuint',
                   'operands': [self._readU30],
                   'handler': self._operands_uint},
            0x21: {'name': 'pushundefined', 'operands': []},
            0x1C: {'name': 'pushwith', 'operands': []},
            0x48: {'name': 'returnvalue', 'operands': []},
            0x47: {'name': 'returnvoid', 'operands': []},
            0xA6: {'name': 'rshift', 'operands': []},
            0x63: {'name': 'setlocal', 'operands': [self._readU30]},
            0xD4: {'name': 'setlocal_0', 'operands': []},
            0xD5: {'name': 'setlocal_1', 'operands': []},
            0xD6: {'name': 'setlocal_2', 'operands': []},
            0xD7: {'name': 'setlocal_3', 'operands': []},
            0x6F: {'name': 'setglobalslot', 'operands': [self._readU30]},
            0x61: {'name': 'setproperty',
                   'operands': [self._readU30],
                   'handler': self._operands_multiname},
            0x6D: {'name': 'setslot', 'operands': [self._readU30]},
            0x05: {'name': 'setsuper',
                   'operands': [self._readU30],
                   'handler': self._operands_multiname},
            0xAC: {'name': 'strictequals', 'operands': []},
            0xA1: {'name': 'subtract', 'operands': []},
            0xC6: {'name': 'subtract_i', 'operands': []},
            0x2B: {'name': 'swap', 'operands': []},
            0x03: {'name': 'throw', 'operands': []},
            0x95: {'name': 'typeof', 'operands': []},
            0xA7: {'name': 'urshift', 'operands': []}}

    @property
    def method(self):
        """Method signature index."""
        return self._method

    @property
    def max_stack(self):
        """Maximum number of evaluation stack slots."""
        return self._max_stack

    @property
    def local_count(self):
        """Highest numbered local register used, plus one."""
        return self._local_count

    @property
    def init_scope_depth(self):
        """Init (minimum) scope depth."""
        return self._init_scope_depth

    @property
    def max_scope_depth(self):
        """Maximum scope depth."""
        return self._max_scope_depth

    @property
    def code(self):
        """AVM2 instructions."""
        return self._code

    @property
    def exceptions(self):
        """List of Exception objects."""
        return self._exceptions

    @property
    def traits(self):
      """List of traits."""
      return self._traits

    def _get_operands(self, operands):
        return [func() for func in operands]

    def strip_operands(self):
        """Strip operands from AVM2 code, returning only opcodes."""
        self._data = self.code
        self.p = 0
        stripped = ''
        while self.p < len(self.code):
            opcode = self._readU8()
            stripped += chr(opcode)
            try:
                op_details = self._OPCODES[opcode]
            except KeyError:
                raise ABCdBadOpcode(opcode)
            # Do nothing with operands unless lookupswitch
            operands = self._get_operands(op_details['operands'])
            if op_details['name'] == 'lookupswitch':
                # Second operand is case_count, there are case_count + 1
                # remaining S24 operands.
                for i in xrange(0, operands[1] + 1):
                    self._readS24()
        return stripped

    def disassemble(self):
        """Generator for disassembly information, yielding OpCode."""
        self._data = self.code
        self.p = 0
        while self.p < len(self.code):
            opcode = self._readU8()
            try:
                op_details = self._OPCODES[opcode]
            except KeyError:
                raise ABCdBadOpcode(opcode)
            operands = self._get_operands(op_details['operands'])
            if op_details['name'] == 'lookupswitch':
                # Second operand is case_count, there are case_count + 1
                # remaining S24 operands.
                for i in xrange(0, operands[1] + 1):
                    operands.append(self._readS24())

            # Resolve any operands using handler...
            try:
                operands = op_details['handler'](operands)
            except:
                # No handler, or problem in handler...
                pass

            yield OpCode(opcode, operands, op_details['name'])

    def _operands_string(self, operands):
        return [self._parser.strings[operand] for operand in operands]

    def _operands_uint(self, operands):
        return [self._parser.uints[operand] for operand in operands]

    def _operands_int(self, operands):
        return [self._parser.ints[operand] for operand in operands]

    def _operands_double(self, operands):
        return [self._parser.doubles[operand] for operand in operands]

    def _operands_multiname(self, operands):
        return [self._parser.resolve_multiname(operand) for operand in operands]

    def _operands_namespace(self, operands):
        result = []
        for operand in operands:
            ns = self.parser.namespaces[operand]
            name = ns.name
            kind = self._parser.CONST_KIND[ns.kind]
            result.append("%s: %s" % (kind, name))
        return result

    def _operands_method_info(self, operands):
        return [str(self._parser.methods[operand]) for operand in operands]

    def _operands_exception(self, operands):
        return [str(self.exceptions[operand]) for operand in operands]

    def _operands_multiname_and_arg(self, operands):
        # Make a copy of operands, as to not alter the mutable list.
        result = list(operands)
        # Element 0 is index into multiname, Element 1 is arg_count.
        result[0] = self._parser.resolve_multiname(operands[0])
        return result

    def _operands_method_info_and_arg(self, operands):
        # Make a copy of operands, as to not alter the mutable list.
        result = list(operands)
        # Element 0 is index into methods, Element 1 is arg_count.
        try:
            result[0] = str(self._parser.methods[operands[0]])
        except:
            pass
        return result

class Trait(object):
    def __init__(self, name, kind, data, metadata):
        if name == 0:
            raise ABCdBadValue("Invalid trait name", name)
        self._name = name
        self._kind = kind
        self._data = data
        self._metadata = metadata

    @property
    def name(self):
        """Name index."""
        return self._name

    @property
    def kind(self):
        """Trait kind, unmodified."""
        return self._kind

    @property
    def data(self):
        """Trait data, interpretation depends on low nibble of kind."""
        return self._data

    @property
    def metadata(self):
        """List of indices into metadata array."""
        return self._metadata

class Slot_Trait(object):
    def __init__(self, slot_id, type_name, vindex, vkind):
        self._slot_id = slot_id
        self._type_name = type_name
        self._vindex = vindex
        self._vkind = vkind

    @property
    def slot_id(self):
        """Position in which this trait resides."""
        return self._slot_id

    @property
    def type_name(self):
        """Index into multiname."""
        return self._type_name

    @property
    def vindex(self):
        """Index into a constant pool array. Depending upon value of vkind."""
        return self._vindex

    @property
    def vkind(self):
        """The kind of constant vindex references."""
        return self._vkind

class Class_Trait(object):
    def __init__(self, slot_id, classi):
        self._slot_id = slot_id
        self._classi = classi

    @property
    def slot_id(self):
        """Position in which this trait resides."""
        return self._slot_id

    @property
    def classi(self):
        """Class index."""
        return self._classi

class Function_Trait(object):
    def __init__(self, slot_id, function):
        self._slot_id = slot_id
        self._function = function

    @property
    def slot_id(self):
        """Position in which this trait resides."""
        return self._slot_id

    @property
    def function(self):
        """Method index."""
        return self._function

class Method_Trait(object):
    def __init__(self, disp_id, method):
        self._disp_id = disp_id
        self._method = method

    @property
    def disp_id(self):
        """Display ID."""
        return self._disp_id

    @property
    def method(self):
        """Method index."""
        return self._method

class ASException(object):
    def __init__(self, from_, to, target, exc_type, var_name, parser):
        self._from = from_
        self._to = to
        self._target = target
        self._exc_type = exc_type
        self._var_name = var_name
        self._parser = parser

    @property
    def from_(self):
        """Starting position from which this exception is enabled."""
        return self._from

    @property
    def to(self):
        """Ending position after which this exception is disabled."""
        return self._to

    @property
    def exc_type(self):
        """Multiname of the exception."""
        return self._exc_type

    @property
    def var_name(self):
        """Multiname of the exception variable name."""
        return self._var_name

    # AVM2 docs say exc_type and var_name are indexes into strings array, which
    # is wrong. They are actually indexes into the multiname array.
    def __str__(self):
        if self.exc_type == 0:
            etype = "*"
        else:
            etype = self._parser.resolve_multiname(self.exc_type)

        if self.var_name != 0:
            return "%s as %s" % (etype,
                                 self._parser.resolve_multiname(self.var_name))
        else:
            return etype
