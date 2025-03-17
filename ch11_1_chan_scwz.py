#***************************************************************************
# Project :    JSF FTI FWD (FireWire DAU)
#
# File    :    ch11_1_chan_scwz.py
#
# Purpose :    Parse a Ch11 packet file from an FWD into hdr, 2nd hdr, CSDW, and IPH
#
# Related Documents: CALCULEX FWD ICD has 5 publish output packet types
#
# Created by Calculex Inc.
#***************************************************************************
# Design Engineer:  M. Small
# Quality Engineer: TBD
# Creation Date:  April 7, 2024
#
# Copyright (c) 2024 by CALCULEX, Inc.    All Rights Reserved
#************************************************************************
###   The contents of this file are the confidential and proprietary  ###
###   property of CALCULEX, Inc. and may not be copied, distributed,  ###
###   or used for any purpose not specifically authorized in writing  ###
###   by CALCULEX, Inc.
#************************************************************************
# File History
#
# 24040713  MJS Initial Testing
#
#*****************************************************************************
#
# Note: all FWD packets have secondary headers
# Note: all IPH use 64-bit UTC time (sec.nano)
#
# 1. get the file byte length and open the input file and an output .hdrs file
# 2. loop processing packets
# 3.  read 40-byte packet header (includes CSDW)
# 4.  calculate remaining bytes in packet and remaining file byte (after this packet)
# 5 extract number of messages or select signals from the CSDW based on data-type
# 6.  print a formatted packet header
# 7.  loop processing messages/signals
# 8.  break when end of packet
# 9. break when end of file
#
import os
import sys

pkt_hdr_len = 40

hdr_bptr = 0

sub_mask = 0x03

scwz_mask = 0x3C

input_file_size = os.path.getsize(sys.argv[1])

#----------------------------------------------------------------------------------
#                   open the .pcap file and get the channel_id
#----------------------------------------------------------------------------------

with open(sys.argv[1], 'rb') as f_in:
#, \
#     open(sys.argv[2] + '.hdrs', 'wb') as f_out:

    chan_in = int(sys.argv[2])

    f_handles = {}
    print(f'\nFile Size (bytes): {input_file_size}')
    input_file_bytes = int(input_file_size)

    while input_file_bytes > 0:           # process packets loop

        pkt_leader = f_in.read(40)
        input_file_bytes = input_file_bytes - 40          # all packets have a 40-byte header+CSDW

        chan_num = int(pkt_leader[2])
        pkt_bytes = int(pkt_leader[4]) + (int(pkt_leader[5])<<8)
        seq_num = int(pkt_leader[13])
        data_type = int(pkt_leader[15])     # 48=SS, 80=H&S, 88=1394, 95=FWD_Debug=0x5F=Reserved_1394
        trans_cnt = int(pkt_leader[36]) + (int(pkt_leader[37])<<8)

        if chan_num == chan_in:
            print(f'Chan: {chan_num}, PktLen: {pkt_bytes}, SeqNum: {seq_num}, Type: {data_type}, Trans: {trans_cnt}')
            if trans_cnt == 0:
                print(f'This is 1394 Bus Reset Packet')

            pkt_bytes = pkt_bytes - 40          # still includes packet trailer (filler+checksum) in addition to all packet data - CSDW

            pkt_data = f_in.read(pkt_bytes)     # includes trailer/checksum
            input_file_bytes = input_file_bytes - pkt_bytes

            data_bytes = int(pkt_leader[8]) + int(pkt_leader[9])*256 - 4      # already consumed the CSDW above
            data_ptr = 0
            item_ctr = 1
            while trans_cnt > 0:
                nano = int(pkt_data[data_ptr]) + (int(pkt_data[data_ptr+1])*256) + (int(pkt_data[data_ptr+2])*16384) + (int(pkt_data[data_ptr+3])*16777216)
                second = int(pkt_data[data_ptr+4]) + (int(pkt_data[data_ptr+5])*256) + (int(pkt_data[data_ptr+6])*16384) + (int(pkt_data[data_ptr+7])*16777216)
                trans_cnt = trans_cnt - 1
                if data_type == 88:
                    msg_len =int(pkt_data[data_ptr+8])*256 + int(pkt_data[data_ptr+9])          # length from 1394 header word excludes 12-byte 1394 wrapper = LM message length
                    vmc_chan = int(pkt_data[data_ptr+10])
                    if vmc_chan == 31:
                        print(f'Item: {item_ctr}, Nano: {nano}, Second: {second}, LM_len: {msg_len}, VMC_chan: {vmc_chan}, STOF')
                    else:
                        msg_id = int(pkt_data[data_ptr+19]) + (int(pkt_data[data_ptr+18])*256) + (int(pkt_data[data_ptr+17])*16384) + (int(pkt_data[data_ptr+16])*16777216)
                        print(f'Item: {item_ctr}, Nano: {nano}, Second: {second}, LM_len: {msg_len}, VMC_chan: {vmc_chan}, MsgID: {msg_id}')
                    item_ctr = item_ctr + 1
                    data_ptr = data_ptr + msg_len + 20
                if data_type == 48:
                    ss_len = int(pkt_data[data_ptr+8]) + int(pkt_data[data_ptr+9])*256
                    ss_sub = int(pkt_data[data_ptr+10]) + int(pkt_data[data_ptr+11]  & sub_mask)*256
                    ss_sel = int((pkt_data[data_ptr+11] & scwz_mask) >> 2)
                    print(f'Item: {item_ctr}, Nano: {nano}, Second: {second}, SS_len: {ss_len}, SS_chan: {ss_sub}, SS_sel: {ss_sel}')
                    item_ctr = item_ctr + 1
                    data_ptr = data_ptr + ss_len + 12
        else:
            pkt_data = f_in.read(pkt_bytes)     # includes trailer/checksum
            input_file_bytes = input_file_bytes - pkt_bytes

for key in f_handles:
    f_handles[key].close()
