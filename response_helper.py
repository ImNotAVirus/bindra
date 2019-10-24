#!/usr/bin/env python
# -*- coding: utf-8 -*-
from contextlib import contextmanager

# https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/DecompileProcess.java
command_start = b'\x00\x00\x01\x02'
command_end = b'\x00\x00\x01\x03'
query_response_start = b'\x00\x00\x01\x08'
query_response_end = b'\x00\x00\x01\x09'
string_start = b'\x00\x00\x01\x0e'
string_end = b'\x00\x00\x01\x0f'
exception_start = b'\x00\x00\x01\x0a'
exception_end = b'\x00\x00\x01\x0b'
byte_start = b'\x00\x00\x01\x0c'
byte_end = b'\x00\x00\x01\x0d'


@contextmanager
# def write_command(stdin: IO) -> Iterator[IO]:
def write_command(stdin):
    stdin.write(command_start)
    yield stdin
    stdin.write(command_end)
    stdin.flush()


@contextmanager
# def write_query_response(stdin: IO) -> Iterator[IO]:
def write_query_response(stdin):
    stdin.write(query_response_start)
    yield stdin
    stdin.write(query_response_end)
    stdin.flush()


# def write_string(stdin: IO, data: bytes) -> None:
def write_string(stdin, data):
    stdin.write(string_start + data + string_end)


# def write_bytes(stdin: IO, data: bytes) -> None:
def write_bytes(stdin, data):
    sz = len(data)

    stdin.write(string_start)
    stdin.write(chr((sz & 0x3f) + 0x20).encode())
    sz = sz >> 6
    stdin.write(chr((sz & 0x3f) + 0x20).encode())
    sz = sz >> 6
    stdin.write(chr((sz & 0x3f) + 0x20).encode())
    sz = sz >> 6
    stdin.write(chr((sz & 0x3f) + 0x20).encode())
    stdin.write(data)
    stdin.write(string_end)
