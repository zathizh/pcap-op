from pcapfile import savefile
import sys
import binascii
import struct
op_num = ('1400', '1500', '1600', '1700', '1800', '1900')
testcap = open(sys.argv[1], 'rb')
capfile = savefile.load_savefile(testcap, layers=1, verbose=True)
print(capfile)
count = 1
for pkt in capfile.packets:
	if (pkt.packet.payload[80:84] == "0500" and pkt.packet.payload[124:128] in op_num):
		print("packet ==== > " + str(count))
		print(pkt.packet.payload[:4] + "," + \
		pkt.packet.payload[4:8] + "," + \
		pkt.packet.payload[8:12] + "," + \
		pkt.packet.payload[12:14] + "," + \
		pkt.packet.payload[14:16] + "," + \
		pkt.packet.payload[16:18] + "," + \
		pkt.packet.payload[18:20] + "," + \
		pkt.packet.payload[20:24] + "," + \
		pkt.packet.payload[24:32] + "," + \
		pkt.packet.payload[32:40] + "," + \

		pkt.packet.payload[40:44] + ","  + \
		pkt.packet.payload[44:48] + ","  + \
		pkt.packet.payload[48:56] + ","  + \
		pkt.packet.payload[56:64] + ","  + \
		pkt.packet.payload[64:68] + ","  + \
		pkt.packet.payload[68:72] + ","  + \
		pkt.packet.payload[72:76] + ","  + \
		pkt.packet.payload[76:80] + ","  + \

		pkt.packet.payload[80:82] + "," + \
		pkt.packet.payload[82:84] + "," + \
		pkt.packet.payload[84:86] + "," + \
		pkt.packet.payload[86:88] + "," + \
		pkt.packet.payload[88:96] + "," + \
		pkt.packet.payload[96:100] + "," + \
		pkt.packet.payload[100:104] + "," + \
		pkt.packet.payload[104:112] + "," + \
		pkt.packet.payload[112:120] + "," + \
		pkt.packet.payload[120:124] + "," + \
		pkt.packet.payload[124:128] + "," + \
		pkt.packet.payload[128:160] + "," + \

		pkt.packet.payload[160:-48] + "," + \

		pkt.packet.payload[-48:-46] + "," + \
		pkt.packet.payload[-46:-44] + "," + \
		pkt.packet.payload[-44:-42] + "," + \
		pkt.packet.payload[-42:-40] + "," + \
		pkt.packet.payload[-40:-32] + "," + \
		pkt.packet.payload[-32:] \
		)

	count = count + 1
	
