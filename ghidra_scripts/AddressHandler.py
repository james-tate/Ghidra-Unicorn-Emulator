import argparse
import binascii
import random 
parser = argparse.ArgumentParser()
parser.add_argument('-ad', default='0000', help='CURRENT PC Address')
parser.add_argument('-R0', default='0000', help='R0 input Value')
parser.add_argument('-R1', default='0000', help='R1 input Value')
parser.add_argument('-R2', default='0000', help='R2 input Value')
parser.add_argument('-R3', default='0000', help='R3 input Value')
parser.add_argument('-R4', default='0000', help='R4 input Value')
parser.add_argument('-R5', default='0000', help='R5 input Value')
parser.add_argument('-R6', default='0000', help='R6 input Value')
parser.add_argument('-R7', default='0000', help='R7 input Value')
parser.add_argument('-R8', default='0000', help='R8 input Value')
parser.add_argument('-R9', default='0000', help='R9 input Value')
parser.add_argument('-R10', default='0000', help='R10 input Value')
parser.add_argument('-R11', default='0000', help='R11 input Value')
parser.add_argument('-R12', default='0000', help='R12 input Value')
parser.add_argument('-sp', default='0000', help='SP input Value')
parser.add_argument('-lr', default='0000', help='LR input Value')
parser.add_argument('-pc', default='0000', help='PC input Value')
parser.add_argument('-cpsr', default='0000', help='CPSR input Value')
args = parser.parse_args()

def setRegs():
    #must print R# and 32 bit hex value
    print("R0:0x00{0}".format(random.randint(0,10)))

#add address to handle here
handleAddress = []
handleAddress.append("113df0")
handleAddress.append("113e04")
handleAddress.append("113e14")

for addr in handleAddress:
    if(hex(int(addr, 16)) == hex(int(args.ad))):
        print("Address {0}".format(hex(int(args.ad))))
        #Manually set registers
        #setRegs()
        #move along the PC if needed
        print("PC:{0}".format(hex(int(addr, 16) + 4)))