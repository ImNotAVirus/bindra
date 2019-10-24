#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import select
import subprocess
import ctypes
# from typing import IO, Iterator
from contextlib import contextmanager
from os import path

import binaryninja as bn

import xml.etree.cElementTree as ET
import itertools

from helper import get_os_name, get_file_extension
from burst_handler import handle_burst
from response_helper import write_command, write_query_response, write_string

# TODO: Retrieve it later from Binary Ninja options
GHIDRA_PATH = 'some/path/to/ghidra_9.1'
DECOMPILER_SUBFOLDER = 'Ghidra/Features/Decompiler/os/{}/decompile{}'.format(
    get_os_name(), get_file_extension())


## Binding Ghidra => Binja

def _get_ghidra_arch_path(binja_arch_name):
    arch_map = {
        'x86': 'x86',
        'x86_64': 'x86',
        # 'armv7': 'ARM',
        # 'armv7eb': 'ARM',
        # 'thumb2': 'ARM',      # ????
        # 'thumb2eb': 'ARM',    # ????
        # 'ppc': 'PowerPC',
        # 'mips32': 'MIPS',
        # 'mipsel32': 'MIPS',
        # 'aarch64': 'AARCH64'
    }

    res = arch_map.get(binja_arch_name)

    if not res:
        raise RuntimeError('Unsupported architecture {!r}'.format(binja_arch_name))
    return 'Ghidra/Processors/{}'.format(res)


def _get_ghidra_arch_prefix(binja_arch_name):
    arch_map = {
        'x86': 'x86',
        'x86_64': 'x86-64',
        # 'armv7': 'ARM',
        # 'armv7eb': 'ARM',
        # 'thumb2': 'ARM',      # ????
        # 'thumb2eb': 'ARM',    # ????
        # 'ppc': 'ppc_32',      # or 'ppc_64' ????
        # 'mips32': 'mips32',   # or 'mips64' ????
        # 'mipsel32': 'MIPS',   # ????
        # 'aarch64': 'AARCH64'
    }

    res = arch_map.get(binja_arch_name)

    if not res:
        raise RuntimeError('Unsupported architecture {!r}'.format(binja_arch_name))
    return res


# bv.arch + bv.view_type = Processor:Endian:AddressSize::CompilerID
# x86_64 + Mach-O = x86:LE:64:default:gcc
# armv7 + ELF = ARM:LE:32:v8:default
def _get_ghidra_compiler(binja_arch_name, binja_view_type):
    if binja_arch_name != 'x86' and binja_arch_name != 'x86_64':
        return ''

    compiler_map = {
        'PE': 'win',
        'ELF': 'gcc',
        'Mach-O': 'gcc'
    }

    res = compiler_map.get(binja_view_type)

    if not res:
        raise RuntimeError('Unsupported view type {!r}'.format(binja_view_type))
    return res


def get_ghidra_pspec_path(bv):
    arch_path = _get_ghidra_arch_path(bv.arch.name)
    arch_prefix = _get_ghidra_arch_prefix(bv.arch.name)
    return '{}/data/languages/{}.pspec'.format(arch_path, arch_prefix)


def get_ghidra_cspec_path(bv):
    arch_path = _get_ghidra_arch_path(bv.arch.name)
    arch_prefix = _get_ghidra_arch_prefix(bv.arch.name)
    compiler = _get_ghidra_compiler(bv.arch.name, bv.view_type)
    compiler = compiler if bv.arch.name != 'x86_64' else '-' + compiler

    return '{}/data/languages/{}{}.cspec'.format(arch_path, arch_prefix, compiler)


## Ghidra Type factory

# https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Framework
#    /SoftwareModeling/src/main/java/ghidra/program/model/pcode/PcodeDataTypeManager.java#L70
def hash_name(name):
    res = ctypes.c_ulonglong(123)

    for i in range(len(name)):
        res.value = (res.value << 8) | (res.value >> 56)
        res.value += ord(name[i])
        if ((res.value & 1) == 0):
            res.value ^= 0x00000000feabfeab

    res.value |= 0x8000000000000000
    return ctypes.c_longlong(res.value).value


# https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/type.hh#L29
class DecompilerTypeEnum:
    TYPE_VOID = 10,		    # ///< Standard "void" type, absence of type
    TYPE_SPACEBASE = 9,		# ///< Placeholder for symbol/type look-up calculations
    TYPE_UNKNOWN = 8,		# ///< An unknown low-level type. Treated as an unsigned integer.
    TYPE_INT = 7,			# ///< Signed integer. Signed is considered less specific than unsigned in C
    TYPE_UINT = 6,		    # ///< Unsigned integer
    TYPE_BOOL = 5,		    # ///< Boolean
    TYPE_CODE = 4,		    # ///< Data is actual executable code
    TYPE_FLOAT = 3,		    # ///< Floating-point
    TYPE_PTR = 2,			# ///< Pointer data-type
    TYPE_ARRAY = 1,		    # ///< Array data-type, made up of a sequence of "element" datatype
    TYPE_STRUCT = 0		    # ///< Structure data-type, made up of component datatypes


class DecompilerType:
    def __init__(self, dname, dsize, dtype, is_unicode=False):
        self.name = dname
        self.size = dsize
        self.type = dtype
        self.is_unicode = is_unicode
        self.id = None if dtype == DecompilerTypeEnum.TYPE_VOID else hash_name(dname)

    def __str__(self):
        return ET.tostring(self.to_xml_node())

    def __repr__(self):
        return str(self)

    def to_xml_node(self):
        if self.type == DecompilerTypeEnum.TYPE_VOID:
            return ET.Element('void')

        metatype_map = {
            DecompilerTypeEnum.TYPE_UNKNOWN: 'unknown',
            DecompilerTypeEnum.TYPE_INT: 'int',
            DecompilerTypeEnum.TYPE_UINT: 'uint',
            DecompilerTypeEnum.TYPE_BOOL: 'bool',
            DecompilerTypeEnum.TYPE_CODE: 'code',
            DecompilerTypeEnum.TYPE_FLOAT: 'float',
        }

        meta = metatype_map.get(self.type)

        if not meta:
            raise RuntimeError('Unsupported type {!r}'.format(self.type))

        res = ET.Element('type', name=self.name, size=str(self.size), metatype=meta, id=str(self.id))

        if self.is_unicode:
            res.attrib['utf'] = 'true'

        return res


## Ghidra decompiler API helpers

def build_ghidra_types():
    res = ET.Element('coretypes')

    res.append(DecompilerType("void", 1, DecompilerTypeEnum.TYPE_VOID).to_xml_node())
    res.append(DecompilerType("bool", 1, DecompilerTypeEnum.TYPE_BOOL).to_xml_node())
    res.append(DecompilerType("uint8_t", 1, DecompilerTypeEnum.TYPE_UINT).to_xml_node())
    res.append(DecompilerType("uint16_t", 2, DecompilerTypeEnum.TYPE_UINT).to_xml_node())
    res.append(DecompilerType("uint32_t", 4, DecompilerTypeEnum.TYPE_UINT).to_xml_node())
    res.append(DecompilerType("uint64_t", 8, DecompilerTypeEnum.TYPE_UINT).to_xml_node())
    res.append(DecompilerType("char", 1, DecompilerTypeEnum.TYPE_INT, True).to_xml_node())
    res.append(DecompilerType("wchar", 2, DecompilerTypeEnum.TYPE_INT, True).to_xml_node())
    res.append(DecompilerType("int8_t", 1, DecompilerTypeEnum.TYPE_INT).to_xml_node())
    res.append(DecompilerType("int16_t", 2, DecompilerTypeEnum.TYPE_INT).to_xml_node())
    res.append(DecompilerType("int32_t", 4, DecompilerTypeEnum.TYPE_INT).to_xml_node())
    res.append(DecompilerType("int64_t", 8, DecompilerTypeEnum.TYPE_INT).to_xml_node())
    res.append(DecompilerType("float", 4, DecompilerTypeEnum.TYPE_FLOAT).to_xml_node())
    res.append(DecompilerType("double", 8, DecompilerTypeEnum.TYPE_FLOAT).to_xml_node())
    res.append(DecompilerType("float16", 16 ,DecompilerTypeEnum.TYPE_FLOAT).to_xml_node())
    res.append(DecompilerType("undefined", 1, DecompilerTypeEnum.TYPE_UNKNOWN).to_xml_node())
    res.append(DecompilerType("undefined2", 2, DecompilerTypeEnum.TYPE_UNKNOWN).to_xml_node())
    res.append(DecompilerType("undefined4", 4, DecompilerTypeEnum.TYPE_UNKNOWN).to_xml_node())
    res.append(DecompilerType("undefined8", 8, DecompilerTypeEnum.TYPE_UNKNOWN).to_xml_node())
    res.append(DecompilerType("code", 1, DecompilerTypeEnum.TYPE_CODE).to_xml_node())

    return ET.tostring(res)


def register_program(proc, bv):
    with write_command(proc.stdin) as f:
        write_string(f, b'registerProgram')

        # pspecxml
        with open(os.path.join(GHIDRA_PATH, get_ghidra_pspec_path(bv)), 'rb') as content_file:
            content = content_file.read()
            write_string(f, content)

        # cspecxml
        with open(os.path.join(GHIDRA_PATH, get_ghidra_cspec_path(bv)), 'rb') as content_file:
            content = content_file.read()
            write_string(f, content)

        # tspecxml
        write_string(f, b'''<sleigh bigendian="%s" uniqbase="0x10000000">
            <spaces defaultspace="ram">
                <space_unique name="unique" index="1" size="4" bigendian="false" delay="0" physical="true" global="false"/>
                <space name="ram" index="2" size="8" bigendian="false" delay="1" physical="true" global="true"/>
                <space name="register" index="3" size="4" bigendian="false" delay="0" physical="true" global="false"/>
            </spaces>
        </sleigh>''' % ('true' if bv.endianness == bn.Endianness.BigEndian else 'false'))

        # coretypesxml
        write_string(f, build_ghidra_types().encode())


def decompile_at(proc, addr):
    with write_command(proc.stdin) as f:
        write_string(f, b'decompileAt')
        write_string(f, b'0')
        write_string(f, b'<addr space="ram" offset="{}"/>'.format(hex(addr)))


def test_bindra(bv):
    args = [path.join(GHIDRA_PATH, DECOMPILER_SUBFOLDER)]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stdin=subprocess.PIPE, bufsize=4096)

    ## Register part
    register_program(proc, bv)
    arch_id = handle_burst(proc, bv)

    # Try a decompilation
    decompile_at(proc, 0x4014a9)
    decompiled_func = handle_burst(proc, bv)

    proc.kill()


bn.PluginCommand.register('Try decompiler', 'Try decompiler...', test_bindra)
