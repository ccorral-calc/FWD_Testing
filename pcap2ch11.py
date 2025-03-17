#***************************************************************************
# Project :    JSF FTI FWD (FireWire DAU)
#
# File    :    pcap2ch11.py
#
# Purpose :    Generate a .ch10 file from an FWD publish .pcap file
#
# Related Documents: CALCULEX Debug Mode Reference 240405.pdf
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
# 24040713  MJS Initial Testing
#
#*****************************************************************************
#
# 1. Open .pcap file and .ch10 output file, read 131072 (128KiB) of .pcap file
# 2. find Ch11 Pkt Header via 25eb sync pattern, confirm channel ID, save pktlen
# 3. backup to IP header, confirm 1st fragment, save IP seg length, Ch11 frag len
# 4. calculate Ch11 fragment length from IP segment length
# 5. write Ch11 Pkt fragment to intermediate file, advance ptr, calculate remaining pkt len
#
# 6. if remaining pkt len = 0, jump to step 7
# 7. skip MAC CRC and next header, save IP segment length, return to step 3
# 8. skip MAC CRC and next header, save IP segment length, confirm 1 fragment
#
#
#
#
# Note! Wireshark and Windows together eat the MAC frame CRCs so we will need to add a
# command line parameter to include/exclude CRCs in the various size calculations
#
#
#
#

import os
import sys

PCAP_File_Header_Size = 24
PCAP_Packet_Header_Size = 16

bptr = 0

input_file_size = os.path.getsize(sys.argv[1])

#----------------------------------------------------------------------------------
#                   open the .pcap file and get the channel_id
#----------------------------------------------------------------------------------

with open(sys.argv[1], 'rb') as f, \
     open(sys.argv[2] + '.ch10', 'wb') as f_out:

    CHAN_ID = sys.argv[2]
    f_handles = {}
    print(f'\nFile Size (bytes): {input_file_size}')
    input_file_bytes = int(input_file_size)

    file_hdr = f.read(PCAP_File_Header_Size)
    input_file_bytes = input_file_bytes - 24

    while input_file_bytes > 16:

        pkt_hdr = f.read(PCAP_Packet_Header_Size)
        input_file_bytes = input_file_bytes - 16

        mac_size = pkt_hdr[8] + 256*pkt_hdr[9]

        print(f'MAC_Size: {mac_size}')

        if input_file_bytes >= mac_size:
            mac_frame = f.read(mac_size)
            input_file_bytes = input_file_bytes - mac_size
        else:
            print(f'Remaining file bytes less than next MAC frame length')
            exit(0)

        frag_len = int(mac_frame[16]*256)+int(mac_frame[17])
        print(f'Frag_len: {frag_len}')
        offset = (int(mac_frame[20]*256)+int(mac_frame[21])) & 8191
        print(f'Offset: {offset}')
        if offset == 0:
             f_out.write(mac_frame[46:mac_size])
             print(f'Offset==0 Ch11_size: {(mac_size-46)}')
        else:
             f_out.write(mac_frame[34:mac_size])
             print(f'Offset!=0 Ch11_size: {(mac_size-34)}')

for key in f_handles:
    f_handles[key].close()
