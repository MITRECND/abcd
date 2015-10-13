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

import struct

class ABCdCommon(object):
    def _readString(self):
        # Strings are pascal style, utf8 encoded.
        l = self._readU30()
        if l == 0:
            return ""

        from ABCParser import ABCdParseError
        try:
            result = struct.unpack("%ss" % l, self._data[self.p:self.p + l])[0]
        except IndexError as e:
            raise ABCdParseError(str(e), self.p)
        self.p += l
        return unicode(result, 'utf-8', 'replace')

    def _readD64(self):
        from ABCParser import ABCdParseError
        try:
            result = struct.unpack("<d", self._data[self.p:self.p + 8])[0]
        except IndexError as e:
            raise ABCdParseError(str(e), self.p)
        self.p += 8
        return result

    def _readU8(self):
        from ABCParser import ABCdParseError
        try:
            result = struct.unpack("<B", self._data[self.p])[0]
        except IndexError as e:
            raise ABCdParseError(str(e), self.p)
        self.p += 1
        return result

    def _readU16(self):
        from ABCParser import ABCdParseError
        try:
            result = struct.unpack("<H", self._data[self.p:self.p + 2])[0]
        except IndexError as e:
            raise ABCdParseError(str(e), self.p)
        self.p += 2
        return result

    def _readU30(self):
        return self._readU32() & 0x3FFFFFFF

    def _readU32(self):
        result = self._readU8()
        if (result & 0x00000080) == 0:
            return result
        result = result & 0x0000007F | self._readU8() << 7
        if (result & 0x00004000) == 0:
            return result
        result = result & 0x00003FFF | self._readU8() << 14
        if (result & 0x00200000) == 0:
            return result
        result = result & 0x001FFFFF | self._readU8() << 21
        if (result & 0x10000000) == 0:
            return result
        return result & 0x0FFFFFFF | self._readU8() << 28

    def _readS32(self):
        result = self._readU32()
        if result & 0xFFFFFFFF00000000:
            return result | 0xFFFFFFF000000000
        else:
            return result

    def _readS24(self):
        return self._readU8() | self._readU8() << 8 | self._readU8() << 16

