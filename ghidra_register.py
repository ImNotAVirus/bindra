#!/usr/bin/env python
# -*- coding: utf-8 -*-
import xml.etree.cElementTree as ET


class GhidraRegister:
    def __init__(self, bv, reg_name, offset=0):
        binja_reg = bv.arch.regs.get(reg_name.lower())

        self.offset = offset

        if binja_reg:
            self.size = binja_reg.size
            return

        reg_part = GhidraRegister.__get_reg_part(bv.arch.regs, reg_name)

        if GhidraRegister.__is_flag(reg_name):
            self.size = 1
        elif reg_part is not None:
            (name, size) = reg_part
            self.size = size
        elif not binja_reg:
            raise RuntimeError('Unsupported register {!r} for arch {!r}'.format(reg_name, bv.arch.name))

    def __str__(self):
        return ET.tostring(self.to_xml_node())

    def __repr__(self):
        return str(self)

    def to_xml_node(self):
        return ET.Element('addr', space='register', offset=hex(self.offset), size=str(self.size))

    @staticmethod
    def __is_flag(reg_name):
        return len(reg_name) == 2 and reg_name.lower().endswith('f')

    @staticmethod
    def __get_reg_part(regs, reg_name):
        # XMM0_Qa   =>  xmm0 (first qword)
        if '_' not in reg_name:
            return None

        [name, part] = reg_name.lower().split('_', 1)

        if name not in regs.keys() or len(part) < 2:
            return None

        size_map = {
            'q': 8,
            'd': 4,
            'w': 2,
            'b': 1
        }

        size = size_map.get(part[0])

        if not size:
            return None
        return (name, size)
