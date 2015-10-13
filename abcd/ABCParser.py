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
from internals import *

class ABCdException(Exception):
    def __init__(self):
        pass

class ABCdBadValue(ABCdException):
    def __init__(self, msg, val):
        self.msg = msg
        self.val = val

    def __str__(self):
        return "%s: 0x%x" % (self.msg, self.val)

class ABCdBadOpcode(ABCdException):
    def __init__(self, val):
        self.val = val

    def __str__(self):
        return "Invalid opcode: 0x%x" % self.val

class ABCdParseError(ABCdException):
    def __init__(self, message, offset):
        self.message = message
        self.offset = offset

    def __str__(self):
        return "(%s) %s" % (self.message, self.offset)

class ABCParser(ABCdCommon):
    CONST_INT = 0x03
    CONST_UINT = 0x04
    CONST_DOUBLE = 0x06
    CONST_UTF8 = 0x01

    CONST_KIND = { CONST_INT: 'Int',
                   CONST_UINT: 'UInt',
                   CONST_DOUBLE: 'Double',
                   CONST_UTF8: 'Utf8',
                   0x0B: 'True',
                   0x0A: 'False',
                   0x0C: 'Null',
                   0x00: 'Undefined',
                   0x08: 'Namespace',
                   0x16: 'PackageNamespace',
                   0x17: 'PackageInternalNs',
                   0x18: 'ProtectedNamespace',
                   0x19: 'ExplicitNamespace',
                   0x1A: 'StaticProtectedNs',
                   0x05: 'PrivateNs' }

    MULTINAME_KIND = { 0x07: 'QName',
                       0x0D: 'QNameA',
                       0x0F: 'RTQName',
                       0x10: 'RTQNameA',
                       0x11: 'RTQNameL',
                       0x12: 'RTQNameLA',
                       0x09: 'Multiname',
                       0x0E: 'MultiNameA',
                       0x1B: 'MultiNameL',
                       0x1C: 'MultinameLA',
                       # Undocumented?
                       0x1D: 'TypeName' }

    QNAME = [ 0x07, 0x0D]
    RTQNAME = [ 0x0F, 0x10 ]
    RTQNAMEL = [ 0x11, 0x12 ]
    MULTINAME = [ 0x09, 0x0E ]
    MULTINAMEL = [0x1B, 0x1C ]
    TYPENAME = [ 0x1D ]

    TRAIT_SLOT = 0x00
    TRAIT_METHOD = 0x01
    TRAIT_GETTER = 0x02
    TRAIT_SETTER = 0x03
    TRAIT_CLASS = 0x04
    TRAIT_FUNCTION = 0x05
    TRAIT_CONST = 0x06

    TRAIT_KIND =  { TRAIT_SLOT: 'Slot',
                    TRAIT_METHOD: 'Method',
                    TRAIT_GETTER: 'Getter',
                    TRAIT_SETTER: 'Setter',
                    TRAIT_CLASS: 'Class',
                    TRAIT_FUNCTION: 'Function',
                    TRAIT_CONST: 'Const' }

    SLOT_CONST_TRAIT = [ 0x00, 0x06]
    CLASS_TRAIT = 0x04
    FUNC_TRAIT = 0x05
    METH_GET_SET_TRAIT = [ 0x01, 0x02, 0x03 ]

    ATTR_FINAL = 0x01
    ATTR_OVERRIDE = 0x02
    ATTR_METADATA = 0x04

    from operator import attrgetter

    def __init__(self, data):
        self._data = data
        self.p = 0

        self._minor = 0
        self._major = 0
        self._ints = [0]
        self._uints = [0]
        self._doubles = [float('nan')]
        self._strings = [""]
        self._namespaces = [Namespace(0, 0)]
        self._namespacesets = [[]]
        self._multinames = [[]]
        self._methods = []
        self._metadata = []
        self._instances = []
        self._classes = []
        self._scripts = []
        self._method_bodies = []

    @property
    def minor(self):
        """Minor version parsed from ABC data."""
        return self._minor

    @property
    def major(self):
        """Major version parsed from ABC data."""
        return self._major

    @property
    def ints(self):
        """Integer constants parsed from ABC data."""
        return self._ints

    @property
    def uints(self):
        """Unsigned integer constants parsed from ABC data."""
        return self._uints

    @property
    def doubles(self):
        """Double constants parsed from ABC data."""
        return self._doubles

    @property
    def strings(self):
        """String constants parsed from ABC data."""
        return self._strings

    @property
    def namespaces(self):
        """Namespaces parsed from ABC data."""
        return self._namespaces

    @property
    def namespacesets(self):
        """Namespace sets parsed from ABC data."""
        return self._namespacesets

    @property
    def multinames(self):
        """Multinames parsed from ABC data."""
        return self._multinames

    @property
    def methods(self):
        """Method signatures parsed from ABC data."""
        return self._methods

    @property
    def metadata(self):
        """Metadata parsed from ABC data."""
        return self._metadata

    @property
    def instances(self):
        """Instances parsed from ABC data."""
        return self._instances

    @property
    def classes(self):
        """Classes parsed from ABC data."""
        return self._classes

    @property
    def scripts(self):
        """Scripts parsed from ABC data."""
        return self._scripts

    @property
    def method_bodies(self):
        """Method bodies parsed from ABC data."""
        return self._method_bodies

    def parse(self):
        self._minor = self._readU16()
        self._major = self._readU16()

        self._parse_constant_pool()
        self._parse_method()
        self._parse_metadata()
        self._parse_classes()
        self._parse_scripts()
        self._parse_method_bodies()

    def _parse_constant_pool(self):
        for i in xrange(1, self._readU30()):
            self._ints.append(self._readS32())

        for i in xrange(1, self._readU30()):
            self._uints.append(self._readU32())

        for i in xrange(1, self._readU30()):
            self._doubles.append(self._readD64())

        for i in xrange(1, self._readU30()):
            self._strings.append(self._readString())

        for i in xrange(1, self._readU30()):
            self._namespaces.append(self._readNamespace())

        for i in xrange(1, self._readU30()):
            self._namespacesets.append(self._readNamespaceSet())

        for i in xrange(1, self._readU30()):
            self._multinames.append(self._readMultiname())

    def _parse_method(self):
        for i in xrange(0, self._readU30()):
            self._methods.append(self._readMethod())

    def _parse_metadata(self):
        for i in xrange(0, self._readU30()):
            self.metadata.append(self._readMetadata())

    def _parse_classes(self):
        # This one is slightly different, it parses both instance_info and
        # class_info structures.
        count = self._readU30()
        for i in xrange(0, count):
            self._instances.append(self._readInstance())
        for i in xrange(0, count):
            self._classes.append(self._readClass())

    def _parse_scripts(self):
        for i in xrange(0, self._readU30()):
            init = self._readU30()
            trait_count = self._readU30()
            traits = []
            for x in xrange(0, trait_count):
                traits.append(self._readTrait())
            self._scripts.append(Script(init, traits))

    def _parse_method_bodies(self):
        for i in xrange(0, self._readU30()):
            method = self._readU30()
            max_stack = self._readU30()
            local_count = self._readU30()
            init_scope_depth = self._readU30()
            max_scope_depth = self._readU30()
            code_length = self._readU30()
            code = self._data[self.p:self.p + code_length]
            self.p += code_length
            exception_count = self._readU30()
            exceptions = []
            for x in xrange(0, exception_count):
                exceptions.append(self._readException())
            trait_count = self._readU30()
            traits = []
            for y in xrange(0, trait_count):
                traits.append(self._readTrait())
            self._method_bodies.append(MethodBody(method,
                                                 max_stack,
                                                 local_count,
                                                 init_scope_depth,
                                                 max_scope_depth,
                                                 code,
                                                 exceptions,
                                                 traits,
                                                 parser=self))

    def _readException(self):
        from_ = self._readU30()
        to = self._readU30()
        target = self._readU30()
        exc_type = self._readU30()
        var_name = self._readU30()
        return ASException(from_, to, target, exc_type, var_name, parser=self)

    def _readNamespace(self):
        return Namespace(self._readU8(), self._readU30())

    def _readNamespaceSet(self):
        result = []
        for i in xrange(0, self._readU30()):
            entry = self._readU30()
            if entry == 0:
                raise ABCdBadValue("Entry must not be zero", entry)
            result.append(entry)
        return result

    def _readMultiname(self):
        kind = self._readU8()
        if kind not in self.MULTINAME_KIND:
            raise ABCdBadValue("Unknown multiname", kind)
        if kind in self.QNAME:
            return Multiname_QName(self._readU30(), self._readU30())
        elif kind in self.RTQNAME:
            return Multiname_RTQName(self._readU30())
        elif kind in self.RTQNAMEL:
            return Multiname_RTQNameL()
        elif kind in self.MULTINAME:
            return Multiname_Multiname(self._readU30(), self._readU30())
        elif kind in self.MULTINAMEL:
            return Multiname_MultinameL(self._readU30())
        elif kind in self.TYPENAME: # Undocumented TypeName
            name = self._readU30()
            count = self._readU30()
            params = []
            for i in xrange(0, count):
                params.append(self._readU30())
            return Multiname_Typename(name, params)

    def _readMethod(self):
        param_count = self._readU30()
        return_type = self._readU30()
        param_types = []
        for i in xrange(0, param_count):
            param_types.append(self._readU30())
        name = self._readU30()
        flags = self._readU8()
        option_details = []
        param_names = []
        if flags & 0x08:
            option_count = self._readU30()
            if option_count == 0 or option_count > param_count:
                raise ABCdBadValue("Invalid option count", option_count)
            for i in xrange(0, option_count):
                option_details.append(Option(self._readU30(), self._readU8()))
        if flags & 0x80:
            param_names = []
            for i in xrange(0, param_count):
                param_names.append(self._readU30())
        return Method(return_type,
                      param_types,
                      name,
                      flags,
                      option_details,
                      param_names,
                      parser=self)

    def _readMetadata(self):
        name = self._readU30()
        if name == 0:
            raise ABCdBadValue("Invalid metadata name", name)
        item_count = self._readU30()
        items = []
        for i in xrange(0, item_count):
            items.append(Metadata_Item(self._readU30(), self._readU30()))
        return Metadata(name, items)

    def _readInstance(self):
        name = self._readU30()
        super_name = self._readU30()
        flags = self._readU8()
        protected_ns = (False, 0)
        if flags & 0x08:
            protected_ns = (True, self._readU30())
        intrf_count = self._readU30()
        interfaces = []
        for i in xrange(0, intrf_count):
            interface = self._readU30()
            if interface == 0:
                raise ABCdBadValue("Invalid interface", interface)
            interfaces.append(interface)
        iinit = self._readU30()
        trait_count = self._readU30()
        traits = []
        for i in xrange(0, trait_count):
            traits.append(self._readTrait())
        return Instance(name,
                        super_name,
                        flags,
                        protected_ns,
                        interfaces,
                        iinit,
                        traits)

    def _readClass(self):
        cinit = self._readU30()
        trait_count = self._readU30()
        traits = []
        for i in xrange(0, trait_count):
            traits.append(self._readTrait())
        return Class(cinit, traits)

    def _readTrait(self):
        # The docs say the name must be a QName, but that is not always true.
        # c101d289d36558c6fbe388d32bd32ab4 is an example.
        name = self._readU30()
        if name == 0:
            raise ABCdBadValue("Invalid trait name", name)
        kind = self._readU8()
        kind_low = kind & 0x0F
        if kind_low not in self.TRAIT_KIND:
            raise ABCdBadValue("Invalid trait kind", kind_low)
        if kind_low in self.SLOT_CONST_TRAIT:
            slot_id = self._readU30()
            type_name = self._readU30()
            vindex = self._readU30()
            vkind = 0
            if vindex != 0:
                vkind = self._readU8()
            data = Slot_Trait(slot_id, type_name, vindex, vkind)
        elif kind_low == self.CLASS_TRAIT:
            slot_id = self._readU30()
            classi = self._readU30()
            data = Class_Trait(slot_id, classi)
        elif kind_low == self.FUNC_TRAIT:
            slot_id = self._readU30()
            function = self._readU30()
            data = Function_Trait(slot_id, function)
        elif kind_low in self.METH_GET_SET_TRAIT:
            disp_id = self._readU30()
            method = self._readU30()
            data = Method_Trait(disp_id, method)
        metadata = []
        # Upper nibble are attributes
        attr = (kind & 0xF0) >> 4;
        if attr & self.ATTR_METADATA:
            metadata_count = self._readU30()
            for i in xrange(0, metadata_count):
                metadata.append(self._readU30())
        return Trait(name, kind, data, metadata)

    def resolve_multiname(self, index):
        multiname = self.multinames[index]
        if isinstance(multiname, Multiname_QName):
            if multiname.ns == 0:
                ns = "*"
            else:
                ns = self.strings[self.namespaces[multiname.ns].name]
            if multiname.name == 0:
                name = "*"
            else:
                name = self.strings[multiname.name]
            # Separate ns from name if we have a ns
            if ns != '':
                ns += '.'
            return "%s%s" % (ns, name)
        elif isinstance(multiname, Multiname_RTQName):
            if multiname.name == 0:
                name = "*"
            else:
                name = self.strings[multiname.name]
            return name
        elif isinstance(multiname, Multiname_RTQNameL):
            return ''
        elif isinstance(multiname, Multiname_Multiname):
            ns_set = self.namespacesets[multiname.ns_set]
            name = self.strings[multiname.name]
            return "ns sets: %s name: %s" % (', '.join(str(nss) for nss in ns_set), name)
        elif isinstance(multiname, Multiname_MultinameL):
            ns_set = self.namespacesets[multiname.ns_set]
            result = []
            for ns in ns_set:
                namespace = self.namespaces[ns]
                s = self.CONST_KIND[namespace.kind]
                if namespace.name == 0:
                    result.append("%s:%s" % (s, str(namespace.name)))
                else:
                    result.append("%s:%s" % (s, self.strings[namespace.name]))
            return "ns sets: %s" % ', '.join(result)
        elif isinstance(multiname, Multiname_Typename):
            name = self.resolve_multiname(multiname.name)
            params = ', '.join(self.resolve_multiname(param) for param in multiname.params)
            return "name: %s params: %s" % (name, params) # XXX

    def resolve_trait(self, trait):
        if isinstance(trait.data, Slot_Trait):
            slot_id = trait.data.slot_id
            if trait.data.type_name == 0:
                type_name = "*"
            else:
                type_name = self.resolve_multiname(trait.data.type_name)
            return {'slot_id': slot_id, 'type_name': type_name}
        elif isinstance(trait.data, Class_Trait):
            slot_id = trait.data.slot_id
            classi = trait.data.classi
            return {'slot_id': slot_id, 'class_index': classi}
        elif isinstance(trait.data, Function_Trait):
            slot_id = trait.data.slot_id
            function = trait.data.function
            return {'slot_id': slot_id, 'function_index': function}
        elif isinstance(trait.data, Method_Trait):
            disp_id = trait.data.disp_id
            method = trait.data.method
            return {'disp_id': disp_id, 'method_index': method}

    def resolve_optional(self, opt):
        if opt.kind == self.CONST_INT:
            return self.ints[opt.val]
        elif opt.kind == self.CONST_UINT:
            return self.uints[opt.val]
        elif opt.kind == self.CONST_DOUBLE:
            return self.doubles[opt.val]
        elif opt.kind == self.CONST_UTF8:
            return self.strings[opt.val]
        else:
            return opt.val # XXX: Handle namespace constants
