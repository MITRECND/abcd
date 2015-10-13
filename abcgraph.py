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
import cgi
import json
import hashlib
import binascii
import argparse

from abcd import ABCParser
from abcd.ABCParser import ABCdException as ABCdException

from swf.movie import SWF

import signal
import traceback

signal.signal(signal.SIGUSR1, lambda sig, stack: traceback.print_stack(stack))

def b2a_printable(s):
    result = ''
    for c in map(ord, s):
        if c >= 0x20 and c <= 0x7e:
            result += chr(c)
        else:
            result += '.'
    return result

def hexdump(data):
    result = ''
    for i in range(0, len(data), 16):
        hexstring = ' '.join([binascii.hexlify(a) for a in data[i:i+16]])
        asciistring = b2a_printable(data[i:i+16])
        result += cgi.escape("%07x: %-48s |%-16s|\n" % (i,
                                                        hexstring,
                                                        asciistring))
    return result

def disassembly_to_dict(body):
    result = []
    for instr in body.disassemble():
        result.append({'name': instr.name,
                       'opcode': instr.opcode,
                       'operands': instr.operands})
    return result

def create_method_node(parser,
                       body,
                       nodes,
                       edges,
                       bodies,
                       relate_to,
                       color,
                       label,
                       level):
    if body == None:
        opc_hash = "NO BODY"
        disassembly = []
        dump = ''
    else:
        #opc_hash = hashlib.md5(body.strip_operands()).hexdigest()
        opc_hash = hashlib.md5(body.code).hexdigest()
        disassembly = disassembly_to_dict(body)
        dump = hexdump(body.code)

    if opc_hash in bodies:
        id_ = bodies[opc_hash]
        node = nodes[id_]
        if 'aka' in node:
            node['aka'].append(label)
        else:
            node['aka'] = [label]
        print "     [-] Duplicate method body: %s (%s) (node: %s)" % (opc_hash,
                                                                      label,
                                                                      id_)
        # Don't duplicate edges...
        edge = {'from': id_, 'to': relate_to}
        if edge not in edges:
            edges.append(edge)
    else:
        id_ = len(nodes)
        bodies[opc_hash] = id_
        nodes.append({'label': label,
                      'id': id_,
                      'color': color,
                      'default_color': color,
                      'dump': dump,
                      'disassembly': disassembly,
                      'level': level})
        edges.append({'from': id_, 'to': relate_to})
        print "     [-] New method body: %s (%s) (node: %s)" % (opc_hash,
                                                                label,
                                                                id_)

def add_method(parser,
               meth_index,
               nodes,
               edges,
               bodies,
               relate_to,
               color,
               label,
               level=5):
    # Walk all bodies looking for one that references the provided method
    # index. If found, add a node and edge.
    for body in parser.method_bodies:
        if body.method != meth_index:
            continue

        create_method_node(parser,
                           body,
                           nodes,
                           edges,
                           bodies,
                           relate_to,
                           color,
                           label,
                           level)
        # Got a body for this one, return.
        return

    # Not every method has a body. In this case, create an empty body node.
    create_method_node(parser,
                       None,
                       nodes,
                       edges,
                       bodies,
                       relate_to,
                       color,
                       label,
                       level)

def add_method_nodes(parser, obj, index, nodes, edges, bodies):
    # Walk all traits for this object, looking for methods.
    for trait in obj.traits:
        if (trait.kind & 0x0F) != parser.TRAIT_METHOD:
            continue

        meth_name = parser.resolve_multiname(trait.name)
        meth_index = parser.resolve_trait(trait)['method_index']
        add_method(parser,
                   meth_index,
                   nodes,
                   edges,
                   bodies,
                   index,
                   '#CCBBAA',
                   meth_name)

def get_traits(parser, traits):
    results = []
    for trait in traits:
        t = {}
        t['name'] = parser.resolve_multiname(trait.name)
        t['type'] = parser.TRAIT_KIND[trait.kind & 0x0F]
        results.append(t)
    return results

# Return a list of node indexes this file relates to...
def dump_graph(parser,
               nodes,
               edges,
               args,
               bodies={},
               classes={},
               instances={}):
    indexes = []
    for i, script in enumerate(parser.scripts):
        #sname = "script_%s" % i
        # Make a node for this script. Every script is unique...
        #id_ = len(nodes)
        #nodes.append({'label': sname,
        #              'id': id_,
        #              'color': 'magenta',
        #              'default_color': 'magenta',
        #              'level': 2})
        #indexes.append(id_)
        #script_index = id_
        #print "  [+] Found script: %s" % sname

        for trait in script.traits:
            if (trait.kind & 0x0F) != parser.TRAIT_CLASS:
                continue

            cname = parser.resolve_multiname(trait.name)

            # If filtering and not a match, skip...
            if args.class_names and cname not in args.class_names:
                print "   [-] Skipping class due to filter (%s)" % cname
                continue

            # If we have this class already, just use the node index.
            # Otherwise, make a new node. Relate node to script node.
            if cname in classes:
                class_index = classes[cname]
                print "   [-] Duplicate class: %s (node: %s)!" % (cname,
                                                                  class_index)
            else:
                id_ = len(nodes)
                nodes.append({'label': "class: %s" % cname,
                              'id': id_,
                              'color': '#00CC00',
                              'default_color': '#00CC00',
                              'level': 3})
                classes[cname] = id_
                class_index = id_
                print "   [-] New class: %s (node: %s)!" % (cname, class_index)
            #edges.append({'from': script_index, 'to': class_index})
            indexes.append(class_index)

            # Handle method for script init...
            #add_method(parser,
            #           script.init,
            #           nodes,
            #           edges,
            #           bodies,
            #           class_index,
            #           '#00FFFF',
            #           "script init %s" % cname,
            #           level=5)

            if not args.full:
                continue

            # Make instance node for this class and handle init and method nodes.
            for instance in parser.instances:
                iname = parser.resolve_multiname(instance.name)
                if iname != cname:
                    continue

                # Make a node (or use existing one) for this instance.
                if iname in instances:
                    instance_index = instances[iname]
                    print "    [-] Duplicate instance: %s (node: %s)" % (iname,
                                                                         instance_index)
                else:
                    id_ = len(nodes)
                    traits = get_traits(parser, instance.traits)
                    nodes.append({'label': "instance: %s" % iname,
                                  'id': id_,
                                  'color': 'grey',
                                  'default_color': 'grey',
                                  'traits': traits,
                                  'level': 4})
                    edges.append({'from': class_index, 'to': id_})
                    instances[iname] = id_
                    instance_index = id_
                    print "    [-] New instance: %s (node: %s)" % (iname,
                                                                   instance_index)

                # Handle methods and init for this instance.
                add_method_nodes(parser,
                                 instance,
                                 instance_index,
                                 nodes,
                                 edges,
                                 bodies)

                # Add instance init method too...
                add_method(parser,
                           instance.iinit,
                           nodes,
                           edges,
                           bodies,
                           instance_index,
                           'orange',
                           "instance init %s" % iname,
                           level=5)

                # Got one instance, move along...
                break

            # Make class node for this script and handle init and method nodes.
            for trait in script.traits:
                if (trait.kind & 0x0F) != parser.TRAIT_CLASS:
                    continue

                class_index = parser.resolve_trait(trait)['class_index']
                klass = parser.classes[class_index]

                # Add method for class init.
                add_method(parser,
                           klass.cinit,
                           nodes,
                           edges,
                           bodies,
                           instance_index,
                           'yellow',
                           "class init %s" % cname,
                           level=5)

                add_method_nodes(parser,
                                 klass,
                                 class_index,
                                 nodes,
                                 edges,
                                 bodies)
                break
    return indexes

def __main__():
    parser = argparse.ArgumentParser(description='Dump actionscript stuff.')
    parser.add_argument('-s', '--class_names', action='append',
                        metavar='class', help='class name to dump')
    parser.add_argument('-f', '--full', action='store_true',
                        help='full graph including methods and inits')
    parser.add_argument('-m', '--metadata', action='store_true',
                        help='enable SWF metadata tags')
    parser.add_argument('-b', '--binaries', action='store_true',
                        help='enable SWF binary tags')
    parser.add_argument('files', metavar='file', nargs='+',
                        help='file to parse')
    args = parser.parse_args()

    if not args.files:
       print "[!] Must provide a filename..."
       return

    nodes = []
    edges = []
    binaries = {}
    metadata = {}
    bodies = {}
    classes = {}
    instances = {}
    for file_ in args.files:
        print "[+] Opening file: %s" % file_
        try:
            f = open(file_, 'rb')
        except Exception as e:
            print "[!] %s" % str(e)
            continue
        try:
            swiff = SWF(f)
        except Exception as e:
            print "[!] pyswf failure: %s" % str(e)
            f.close()
            continue
        f.close()

        parser = None
        indexes = []
        # Metadata and binary tags are stored until we have nodes returned
        # for ABC elements. This ensures that we don't create nodes for these
        # tags without also having something else meaningful.
        metadata_tags = []
        binary_tags = []
        for tag in swiff.tags:
            #print "Tag: %s" % tag.name
            if tag.name == "Metadata" and args.metadata:
                metadata_tags.append(tag)
            if tag.name == "TagDefineBinaryData" and args.binaries:
                binary_tags.append(tag)
            elif tag.name in ["DoABC", "DoABCDefine"]:
                if hasattr(tag, 'abcName'):
                    print " [-] ABCName: %s" % tag.abcName
                parser = ABCParser.ABCParser(tag.bytes)
                try:
                    parser.parse()
                except ABCdException as e:
                    print "[!] Parsing error: %s" % str(e)
                    continue

                indexes += dump_graph(parser,
                                      nodes,
                                      edges,
                                      args,
                                      bodies=bodies,
                                      classes=classes,
                                      instances=instances)

        if indexes:
            new_id = len(nodes)
            nodes.append({'id': new_id,
                          'label': os.path.basename(file_),
                          'color': 'purple',
                          'default_color': 'purple',
                          'level': 0})
            # Create edge between this new node and all returned indexes
            for index in indexes:
                edges.append({'from': new_id, 'to': index})

            for tag in metadata_tags:
                # Create a node for metadata blobs.
                md_hash = hashlib.md5(tag.xmlString).hexdigest()
                if md_hash in metadata:
                    mid_id = metadata[md_hash]
                else:
                    md_id = len(nodes)
                    metadata[md_hash] = md_id
                    nodes.append({'id': md_id,
                                  'label': md_hash,
                                  'details': tag.xmlString,
                                  'color': 'blue',
                                  'default_color': 'blue',
                                  'level': 1})
                edges.append({'from': new_id, 'to': md_id})
                print " [-] Metadata: %s" % md_hash
            for tag in binary_tags:
                # Add a node for binary data blobs.
                bin_hash = hashlib.md5(tag.data).hexdigest()
                if bin_hash in binaries:
                    bin_id = binaries[bin_hash]
                else:
                    bin_id = len(nodes)
                    binaries[bin_hash] = bin_id
                    # Include hexdump of first 512 bytes...
                    nodes.append({'id': bin_id,
                                  'label': bin_hash,
                                  'details': "Length: %s" % len(tag.data),
                                  'color': 'pink',
                                  'default_color': 'pink',
                                  'dump': hexdump(tag.data[:512]),
                                  'level': 1})
                edges.append({'from': new_id, 'to': bin_id})
                print " [-] Binary: %s" % bin_hash
        else:
            print "[!] No nodes created..."

    print "[-] Nodes: %s" % len(nodes)
    f = open("nodes.json", 'w')
    f.write(json.dumps(nodes))
    f.close()

    print "[-] Edges: %s" % len(edges)
    f = open("edges.json", 'w')
    f.write(json.dumps(edges))
    f.close()

if __name__ == '__main__':
    __main__()
