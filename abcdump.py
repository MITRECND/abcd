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

import os
import sys
import json
import hashlib
import argparse

from abcd import ABCParser

from swf.movie import SWF

import signal
import traceback

signal.signal(signal.SIGUSR1, lambda sig, stack: traceback.print_stack(stack))

def dump_scripts(parser):
    print "---------------------------------------------------------------"
    for (c, script) in enumerate(parser.scripts):
        print "Dumping script: %s" % c
        print "\tInit method: %s" % script.init
        print "\tTraits: %s" % len(script.traits)
        for trait in script.traits:
            print "\tTrait kind: %s" % (trait.kind & 0x0F)
            # The docs say the name is an index into the multiname list and it
            # must not be zero and the entry in the list must be a QName.
            # I've seen cases where it is not a QName:
            # c101d289d36558c6fbe388d32bd32ab4
            print "\t\tName: %s" % parser.resolve_multiname(trait.name)
            print "\t\tDetails: %s" % parser.resolve_trait(trait)

def dump_classes(parser):
    print "---------------------------------------------------------------"
    for (c, klass) in enumerate(parser.classes):
        print "Dumping class: %s" % c
        print "\tClass init method: %s" % klass.cinit
        print "\tTraits: %s" % len(klass.traits)
        for trait in klass.traits:
            print "\tTrait kind: %s" % (trait.kind & 0x0F)
            print "\t\tName: %s" % parser.resolve_multiname(trait.name)
            print "\t\tDetails: %s" % parser.resolve_trait(trait)

def dump_methods(parser):
    print "---------------------------------------------------------------"
    for (c, method) in enumerate(parser.methods):
        print "Dumping method: %s" % c
        if method.name == 0:
            method_name = "NO NAME"
        else:
            method_name = parser.strings[method.name]
        print "\tMethod name: %s" % method_name
        print "\tMethod flags: 0x%x" % method.flags
        if method.return_type == 0:
            return_type = "*"
        else:
            return_type = parser.resolve_multiname(method.return_type)
        print "\tReturn type: %s" % return_type
        print "\tParam types: %s" % len(method.param_types)
        for param_type in method.param_types:
            if param_type == 0:
                pt = "*"
            else:
                pt = parser.resolve_multiname(param_type)
            print "\t\tDetails: %s" % pt
        print "\tOptionals: %s" % len(method.options)
        for opt in method.options:
            print "\t\tKind: %s" % parser.CONST_KIND[opt.kind]
            print "\t\tVal: %s" % parser.resolve_optional(opt)
        print "\tParameter names: %s" % len(method.param_names)
        for str_idx in method.param_names:
            print "\t\tName: %s (%s)" % (parser.strings[str_idx], str_idx)

def dump_bodies(parser):
    print "---------------------------------------------------------------"
    for (c, body) in enumerate(parser.method_bodies):
        print "Dumping body: %s" % c
        print "\tMethod: %s" % body.method
        print "\tExceptions: %s" % len(body.exceptions)
        print "\tCode length: %s" % len(body.code)
        print "\tCode MD5: %s" % hashlib.md5(body.code).hexdigest()
        print "\tOpcodes MD5: %s" % hashlib.md5(body.strip_operands()).hexdigest()
        print "\tDisassembly:"
        for instr in body.disassemble():
            print "\t%s (%s): %s" % (instr.name,
                                     instr.opcode,
                                     ', '.join(str(op) for op in instr.operands))

def dump_instances(parser):
    print "---------------------------------------------------------------"
    for (c, instance) in enumerate(parser.instances):
        print "Dumping instance: %s" % c
        print "\tName: %s" % parser.resolve_multiname(instance.name)
        if instance.super_name == 0:
            super_name = "NONE"
        else:
            super_name = parser.resolve_multiname(instance.super_name)
        print "\tSuper name: %s" % super_name
        print "\tInstance init: %s" % instance.iinit
        for trait in instance.traits:
            print "\tTrait kind: %s" % (trait.kind & 0x0F)
            print "\t\tName: %s" % parser.resolve_multiname(trait.name)
            print "\t\tDetails: %s" % parser.resolve_trait(trait)

def __main__():
    parser = argparse.ArgumentParser(description='Dump actionscript stuff.')
    parser.add_argument('-s', '--script_names', action='append',
                        metavar='script', help='script name to dump')
    parser.add_argument('files', metavar='file', nargs='+',
                        help='file to parse')
    args = parser.parse_args()

    if not args.files:
       print "Must provide a filename..."
       return

    for file_ in args.files:
        print "Opening file: %s" % file_
        try:
            f = open(file_, 'rb')
        except Exception as e:
            print str(e)
            continue
        try:
            swiff = SWF(f)
        except Exception as e:
            print "pyswf failure: %s" % str(e)
            f.close()
            continue
        f.close()

        parser = None
        for tag in swiff.tags:
            if tag.name in ["DoABC", "DoABC2"]:
                parser = ABCParser.ABCParser(tag.bytes)
                parser.parse()
                #out = open("abc.as", 'wb')
                #out.write(tag.bytes)
                #out.close()
                break # XXX: There can be more than one DoABC tag...

        # XXX: Sometimes pyswf fails to parse things... :(
        if parser:
            dump_scripts(parser)
            dump_classes(parser)
            dump_methods(parser)
            dump_bodies(parser)
            dump_instances(parser)
        else:
            print "Problem finding DoABC..."

if __name__ == '__main__':
    __main__()
