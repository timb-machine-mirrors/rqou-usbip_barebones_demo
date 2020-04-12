#!/usr/bin/env python3

from collections import namedtuple
import socket
import struct

usbip_user_op_common = namedtuple('usbip_user_op_common', 'version code status')
usbip_usb_device = namedtuple('usbip_usb_device', 'path busid busnum devnum speed idVendor idProduct bcdDevice bDeviceClass bDeviceSubClass bDeviceProtocol bConfigurationValue bNumConfigurations bNumInterfaces')

usbip_header_basic = namedtuple('usbip_header_basic', 'command seqnum devid direction ep')
usbip_header_cmd_submit = namedtuple('usbip_header_cmd_submit', 'transfer_flags transfer_buffer_length start_frame number_of_packets interval setup')
usbip_header_ret_submit = namedtuple('usbip_header_ret_submit', 'status actual_length start_frame number_of_packets error_count')

setup_packet = namedtuple('setup_packet', 'bmRequestType bRequest wValue wIndex wLength')

EPIPE = 32

VERSION = 0x111

def recv_or_panic(conn, len_):
    ret = conn.recv(len_)
    if len(ret) != len_:
        print(ret)
        raise Exception("failed to read")
    return ret

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", 3240))
    s.listen()
    conn, addr = s.accept()
    print("Connected to {}".format(addr))

    stash_data = 12345

    is_kernel_mode = False

    while True:
        if not is_kernel_mode:
            op_common_bytes = recv_or_panic(conn, 8)
            op_common = usbip_user_op_common._make(struct.unpack(">HHI", op_common_bytes))
            print(op_common)

            if op_common.version != VERSION:
                raise Exception("invalid version")

            if op_common.code == 0x8003:
                # OP_REQ_IMPORT
                import_busid = recv_or_panic(conn, 32)
                print("importing busid {}".format(import_busid))

                reply_op_common = usbip_user_op_common(VERSION, 0x03, 0)
                # print(reply_op_common)
                reply_op_common_bytes = struct.pack(">HHI", *reply_op_common)
                # print(reply_op_common_bytes)
                reply_usbd = usbip_usb_device(
                    b'',
                    import_busid,
                    0, 0, 3, # high speed
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0)
                # print(reply_usbd)
                reply_usbd_bytes = struct.pack(">256s32sIIIHHHBBBBBB", *reply_usbd)
                # print(len(reply_usbd_bytes), reply_usbd_bytes)
                conn.send(reply_op_common_bytes + reply_usbd_bytes)
                is_kernel_mode = True
                print("Connecting to kernel mode!")
            else:
                raise Exception("unsupported code")
        else:
            header_bytes = recv_or_panic(conn, 48)

            header_basic_bytes = header_bytes[:20]
            header_basic = usbip_header_basic._make(struct.unpack(">IIIII", header_basic_bytes))
            # print(header_basic)

            if header_basic.command == 1:
                # USBIP_CMD_SUBMIT
                header_cmd_submit_bytes = header_bytes[20:48]
                header_cmd_submit = usbip_header_cmd_submit._make(struct.unpack(">Iiiii8s", header_cmd_submit_bytes))
                # print(header_cmd_submit)
                # assert False

                ##### DO STUFF HERE

                reply_data = None

                if header_basic.direction == 1:
                    # IN
                    if header_basic.ep == 0:
                        # control
                        setup_pkt = setup_packet._make(struct.unpack("<BBHHH", header_cmd_submit.setup))
                        print(setup_pkt)

                        if setup_pkt.bRequest == 6:
                            # GET_DESCRIPTOR
                            desc_type = setup_pkt.wValue >> 8
                            desc_index = setup_pkt.wValue & 0xFF

                            print("GET_DESCRIPTOR {} {}".format(desc_type, desc_index))

                            if desc_type == 1:
                                # Device descriptor
                                reply_data = struct.pack("<BBHBBBBHHHBBBB",
                                    18,
                                    1,
                                    0x0210,
                                    0xFF,
                                    0xFF,
                                    0xFF,
                                    8,
                                    0xF055,
                                    0x0000,
                                    0,
                                    0,
                                    0,
                                    0,
                                    1)
                            elif desc_type == 2:
                                # Configuration descriptor
                                reply_data = (struct.pack("<BBHBBBBB",
                                    9,
                                    2,
                                    9 + 9,
                                    0,
                                    1,
                                    0,
                                    0b10000000,
                                    250) +

                                # Interface descriptor
                                struct.pack("<BBBBBBBBB",
                                    9,
                                    4,
                                    0,
                                    0,
                                    0,
                                    0xFF,
                                    0xFF,
                                    0xFF,
                                    0))
                        elif setup_pkt.bRequest == 0xAA:
                            print("SPECIAL TEST REQUEST IN")
                            reply_data = struct.pack("<I", stash_data)
                else:
                    # OUT
                    request_data = recv_or_panic(conn, header_cmd_submit.transfer_buffer_length)
                    print(request_data)

                    if header_basic.ep == 0:
                        # control
                        setup_pkt = setup_packet._make(struct.unpack("<BBHHH", header_cmd_submit.setup))
                        print(setup_pkt)

                        if setup_pkt.bRequest == 9:
                            # SET_CONFIGURATION
                            print("SET_CONFIGURATION {}".format(setup_pkt.wValue))
                            reply_data = b''
                        elif setup_pkt.bRequest == 0xAB:
                            print("SPECIAL TEST REQUEST OUT")
                            if len(request_data) < 4:
                                print("ERROR: TOO SHORT")
                            else:
                                stash_data = struct.unpack("<I", request_data[:4])[0]
                                reply_data = b''

                ##### SEND REPLY
                reply_header_basic = usbip_header_basic(3, header_basic.seqnum, 0, 0, 0)
                if reply_data is None:
                    reply_header_submit = usbip_header_ret_submit(-EPIPE, 0, 0, 0, 0)
                else:
                    if len(reply_data) > header_cmd_submit.transfer_buffer_length:
                        reply_data = reply_data[:header_cmd_submit.transfer_buffer_length]
                    reply_header_submit = usbip_header_ret_submit(0, len(reply_data), 0, 0, 0)
                reply_header_bytes = struct.pack(">IIIII", *reply_header_basic) + struct.pack(">iiiii", *reply_header_submit) + b'\x00\x00\x00\x00\x00\x00\x00\x00'
                conn.send(reply_header_bytes)
                if reply_data is not None:
                    conn.send(reply_data)
                # TODO: isoc
            elif header_basic.command == 2:
                # USBIP_CMD_UNLINK
                seqnum_byts = header_bytes[20:24]
                seqnum = struct.unpack(">I", seqnum_byts)[0]
                print(seqnum)

                # TODO?
            else:
                raise Exception("unsupported command")

if __name__ == '__main__':
    main()
