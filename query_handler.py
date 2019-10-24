#!/usr/bin/env python
# -*- coding: utf-8 -*-
import xml.etree.cElementTree as ET

from response_helper import write_query_response, write_string, write_bytes
from ghidra_register import GhidraRegister


# ['getUserOpName', '0']
def getUserOpName(proc, _bv, _):
    with write_query_response(proc.stdin) as f:
        write_string(f, b'')


# ['getRegister', 'RAX']
def getRegister(proc, bv, reg_name):
    # TODO: set offset
    res = GhidraRegister(bv, reg_name, offset=0)

    print(res)
    with write_query_response(proc.stdin) as f:
        write_string(f, str(res).encode())


# ['getMappedSymbolsXML', '<addr space="ram" offset="0x4014a9"/>']
def getMappedSymbolsXML(proc, bv, addr_info):
    with write_query_response(proc.stdin) as f:
        write_string(f, b'''
            <result>
                <parent>
                    <val/>
                </parent>
                <mapsym>
                    <function name="sub_4014a9" size="1">
                        <addr space="ram" offset="0x4014a9"/>
                        <localdb lock="false" main="stack">
                            <scope name="sub_4014a9">
                                <parent>
                                    <val/>
                                </parent>
                                <rangelist/>
                                <symbollist></symbollist>
                            </scope>
                        </localdb>
                        <prototype extrapop="8" model="unknown">
                            <returnsym>
                                <addr space="register" offset="0x0" size="1"/>
                                <typeref name="undefined"/>
                            </returnsym>
                        </prototype>
                    </function>
                    <addr space="ram" offset="0x4014a9"/>
                    <rangelist/>
                </mapsym>
            </result>
        ''')


# ['getPacked', <addr space="ram" offset="0x4014a9"/>']
def getPacked(proc, bv, addr_info):
    with write_query_response(proc.stdin) as f:
        write_bytes(f, b"!!`\"4R30`\"\"%#(*`($\"%#@`(`\"3%#@`(%#@`(% (`(`\"*#%#(*`(``")


# ['getTrackedRegisters', <addr space="ram" offset="0x4014a9"/>']
def getTrackedRegisters(proc, bv, addr_info):
    with write_query_response(proc.stdin) as f:
        write_string(f, '<tracked_pointset space="ram" offset="0x4014a9"></tracked_pointset>')


# ['getComments', <addr space="ram" offset="0x4014a9"/>', '58']
def getComments(proc, bv, _addr_info, _flags):
    with write_query_response(proc.stdin) as f:
        write_string(f, '<commentdb></commentdb>')
