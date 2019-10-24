#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

import query_handler


# https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_arch.cc#L33
def __read_to_any_burst(stdout, error=True):
    # /// Code bytes are as follows:
    # ///   - Command                 open=2 close=3
    # ///   - Query                   open=4 close=5
    # ///   - Command response        open=6 close=7
    # ///   - Query response          open=8 close=9
    # ///   - Exception               open=a close=b
    # ///   - Byte stream             open=c close=d
    # ///   - String stream           open=e close=f
    while True:
        c = os.read(stdout.fileno(), 1)
        if c != '\0':
            break

    # Handle decompiler crashs
    if c == '':
        raise RuntimeError('Ghidra decompiler crashed...')

    if c == '\1':
        return ord(os.read(stdout.fileno(), 1))
    elif not error:
        return None

    raise RuntimeError('Corrupted burst: unexpected byte {}'.format(hex(ord(c))))


def __handle_command(proc, _bv, error=True):
    end_of_burst = 0x3
    print('[BINDRA] Handle command')
    raise RuntimeError('Unimplemented handler: handle_command')


def __handle_query(proc, bv, error=True):
    end_of_burst = 0x5
    res = []

    while True:
        tmp = handle_burst(proc, bv, stop_at_type=end_of_burst, error=error)
        if tmp == True:
            break
        res.append(tmp)

    if len(res) < 1:
        if not error:
            return
        raise RuntimeError('Empty query')

    query_name = res[0]
    query_params = res[1:]
    query_func = getattr(query_handler, query_name, None)

    print('[BINDRA] Handle query: {}({!r})'.format(query_name, query_params))

    if query_func is None:
        if not error:
            return
        raise RuntimeError('Unimplemented handler for handle_query: {!r}'.format(query_name))

    return query_func(proc, bv, *query_params)


def __handle_command_resp(proc, bv, error=True):
    end_of_burst = 0x7
    res = None

    print('[BINDRA] Handle command_resp start')

    while True:
        tmp = handle_burst(proc, bv, stop_at_type=end_of_burst, error=error)

        if tmp == True:
            break
        elif tmp is not None:
            res = tmp

    print('[BINDRA] Handle command_resp end: {!r}'.format(res))
    return res


def __handle_query_resp(proc, _bv, error=True):
    end_of_burst = 0x9
    print('[BINDRA] Handle query_resp')
    raise RuntimeError('Unimplemented handler: query_resp')


def __handle_exception(proc, _bv, error=True):
    end_of_burst = 0xb
    print('[BINDRA] Handle exception')
    raise RuntimeError('Unimplemented handler: exception')


def __handle_byte_stream(proc, _bv, error=True):
    end_of_burst = 0xd
    print('[BINDRA] Handle byte_stream')
    raise RuntimeError('Unimplemented handler: byte_stream')


def __handle_string_stream(proc, bv, error=True):
    end_of_burst = 0xf
    res = []
    end_of_string_found = False

    while not end_of_string_found:
        while True:
            c = os.read(proc.stdout.fileno(), 1)
            if c == '\0':
                break
            res.append(c)

        # Wut ??? Sometimes Ghidra insert bursts inside strings xD
        tmp = handle_burst(proc, bv, stop_at_type=end_of_burst, error=error)
        end_of_string_found = tmp == True

    print('[BINDRA] Handle string_stream: {!r}'.format(''.join(res)))
    return ''.join(res)


def __handle_error(proc, _bv, error=True):
    end_of_burst = 0x11
    res = []

    while True:
        c = os.read(proc.stdout.fileno(), 1)
        if c == '\0':
            break
        res.append(c)

    burst_type = __read_to_any_burst(proc.stdout, error=error)

    if burst_type != end_of_burst and error:
        raise RuntimeError('Invalid end of burst for an arror. Expected {} but got {}'
                .format(hex(end_of_burst), hex(burst_type)))

    error_str = ''.join(res).strip()

    if not error_str:
        return

    print('[BINDRA] Ghidra decompiler raised an error: {!r}'.format(error_str))


# https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_arch.cc#L37
def handle_burst(proc, bv, stop_at_type=None, error=True):
    burst_type_map = {
        0x2: __handle_command,
        0x4: __handle_query,
        0x6: __handle_command_resp,
        0x8: __handle_query_resp,
        0xa: __handle_exception,
        0xc: __handle_byte_stream,
        0xe: __handle_string_stream,
        0x10: __handle_error,
    }

    burst_type = __read_to_any_burst(proc.stdout, error=error)

    if stop_at_type is not None and burst_type == stop_at_type:
        return True

    if burst_type not in burst_type_map.keys():
        if not error:
            return False
        raise RuntimeError('Unknown burst type {!r}'.format(hex(burst_type)))

    # Handlers MUSTN'T return True
    return burst_type_map[burst_type](proc, bv, error=error)
