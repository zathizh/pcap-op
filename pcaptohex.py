from pcapfile import savefile
import sys
testcap = open(sys.argv[1], 'rb')
capfile = savefile.load_savefile(testcap, layers=1, verbose=True)
print(capfile)
count = 1
for pkt in capfile.packets:
	print("packet ==== > " + str(count))
	print(pkt.packet.payload)
	count = count + 1
