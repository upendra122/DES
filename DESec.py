#Program DES Encryption 
#By upendra singh bartwal
from bitarray import bitarray
#For expansion of 32 bit into 48
expand = [32,1,2,3,4,5,
       4,5,6,7,8,9,
       8,9,10,11,12,13,
       12,13,14,15,16,17,
       16,17,18,19,20,21,
       20,21,22,23,24,25,
       24,25,26,27,28,29,
       28,29,30,31,32,1]

#for choosing 56 bits of key from 64
pc1 = [57,49,41,33,25,17,9,
       1,58,50,42,34,26,18,
       10,2,59,51,43,35,27,
       19,11,3,60,52,44,36,
       63,55,47,39,31,23,15,
       7,62,54,46,38,30,22,
       14,6,61,53,45,37,29,
       21,13,5,28,20,12,4]
#for choosing 48 bits from 56 (key genration)
pc2 = [14,17,11,24,1,5,
       3,28,15,6,21,10,
       23,19,12,4,26,8,
       16,7,27,20,13,2,
       41,52,31,37,47,55,
       30,40,51,45,33,48,
       44,49,39,56,34,53,
       46,42,50,36,29,32]

#S-Boxes
s1 = [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
      [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
      [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
      [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]]

s2 = [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
      [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
      [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
      [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]]

s3 = [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
      [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
      [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
      [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]]

s4 = [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
      [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
      [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
      [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]]

s5 = [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
      [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
      [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
      [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]]

s6 = [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
      [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
      [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
      [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]]

s7 = [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
      [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
      [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
      [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]]

s8 = [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
      [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
      [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
      [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]

perm = [16,7,20,21,
        29,12,28,17,
        1,15,23,26,
        5,18,31,10,
        2,8,24,14,
        32,27,3,9,
        19,13,30,6,
        22,11,4,25]

#initial permutation of chiper text
ip = [58,50,42,34,26,18,10,2,
      60,52,44,36,28,20,12,4,
      62,54,46,38,30,22,14,6,
      64,56,48,40,32,24,16,8,
      57,49,41,33,25,17,9,1,
      59,51,43,35,27,19,11,3,
      61,53,45,37,29,21,13,5,
      63,55,47,39,31,23,15,7]

ipinv = [8,40,16,48,24,56,32,64,
         7,39,15,47,23,55,31,63,
         6,38,14,46,22,54,30,62,
         5,37,13,45,21,53,29,61,
         4,36,12,44,20,52,28,60,
         3,35,11,43,19,51,27,59,
         2,34,10,42,18,50,26,58,
         1,33,9,41,17,49,25,57]

#shifts operation in key genration         
shifts = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
#only these character allowed
array="fghijklmnopqrstu"
#funciton for calculating 4-bit to decimal
def changeit(a):
	num=2**3*(a[0])+2**2*(a[1])+2*a[2]+a[3]
	return array[num]
#inp=raw_input("Enter the text:: " )
inp="fgfgfgfgfgfgfgfg"
out="nqokqkfljuqnrqus"
#conversion of character to bits f-u are allowed only
def convert(inp):
	temp="{0:b}".format(ord(inp[0])-ord('f'))
	inpb='0'*(4-len(temp))+temp
	lenn=len(inp)
	for i in range(1,lenn):
		temp="{0:b}".format(ord(inp[i])-ord('f'))
		inpb=inpb+'0'*(4-len(temp))+temp
	PlTxt=bitarray(64)	
	for i in range(0,64):
		PlTxt[i]=ord(inpb[i])-ord('0')
	return PlTxt
#shift operation under key genration	
def rotatearr(a,shift):
	b=a[0]
	c=a[1]
	if shift==1:
		for i in range(1,28):
			a[i-1]=a[i]
		a[27]=b
	else:
		for i in range(2,28):
			a[i-2]=a[i]
		a[26]=b
		a[27]=c
	return a
PlTxtip=bitarray(64)
KeyP=bitarray(56)
ExP=bitarray(48)
SO=bitarray(32)

PlTxt=bitarray(64)
PlTxt=convert(inp)
for i in range(0,64):
	PlTxtip[i]=PlTxt[ip[i]-1]
Lhalf=bitarray(32)
Rhalf=bitarray(32)
Lhalf=PlTxtip[0:32]
Rhalf=PlTxtip[32:]
	
for op in range(0,343597383):

	Keyy="{0:b}".format(op)
	lenn=len(Key)
	Keyy='0'*(64-lenn)+Keyy
	Key=bitarray(64)
	for i in range(0,64):
		Key[i]=ord(Keyy[i])-ord('0')
	for i in range(0,56):
		KeyP[i]=Key[pc1[i]-1]
	Lkey=KeyP[0:28]
	Rkey=KeyP[28:]
		
	for k in range(0,16):
	#	print(PlTxt)
		
		for i in range(0,48):
			ExP[i]=Rhalf[expand[i]-1]
		#print(ExP)
		Lkey=rotatearr(Lkey,shifts[k])
		Rkey=rotatearr(Rkey,shifts[k])
		LRkey=Lkey+Rkey
		KeyP2=bitarray(48)
		for i in range(0,48):
			KeyP2[i]=LRkey[pc2[i]-1]
		#print(KeyP2)
		XoredT=bitarray(48)
		for i in range(0,48):
			XoredT[i]=KeyP2[i]^ExP[i]
		#print(XoredT)
		s1I=XoredT[:6]
		s2I=XoredT[6:12]
		s3I=XoredT[12:18]
		s4I=XoredT[18:24]
		s5I=XoredT[24:30]
		s6I=XoredT[30:36]
		s7I=XoredT[36:42]
		s8I=XoredT[42:]
		
		s1O=s1[2*s1I[0]+s1I[5]][2**3*s1I[1]+2**2*s1I[2]+2*s1I[3]+s1I[4]]
		s2O=s2[2*s2I[0]+s2I[5]][2**3*s2I[1]+2**2*s2I[2]+2*s2I[3]+s2I[4]]
		s3O=s3[2*s3I[0]+s3I[5]][2**3*s3I[1]+2**2*s3I[2]+2*s3I[3]+s3I[4]]
		s4O=s4[2*s4I[0]+s4I[5]][2**3*s4I[1]+2**2*s4I[2]+2*s4I[3]+s4I[4]]
		s5O=s5[2*s5I[0]+s5I[5]][2**3*s5I[1]+2**2*s5I[2]+2*s5I[3]+s5I[4]]
		s6O=s6[2*s6I[0]+s6I[5]][2**3*s6I[1]+2**2*s6I[2]+2*s6I[3]+s6I[4]]
		s7O=s7[2*s7I[0]+s7I[5]][2**3*s7I[1]+2**2*s7I[2]+2*s7I[3]+s7I[4]]
		s8O=s8[2*s8I[0]+s8I[5]][2**3*s8I[1]+2**2*s8I[2]+2*s8I[3]+s8I[4]]

		s1Ob='0'*(4-len("{0:b}".format(s1O)))+"{0:b}".format(s1O)
		s2Ob='0'*(4-len("{0:b}".format(s2O)))+"{0:b}".format(s2O)
		s3Ob='0'*(4-len("{0:b}".format(s3O)))+"{0:b}".format(s3O)
		s4Ob='0'*(4-len("{0:b}".format(s4O)))+"{0:b}".format(s4O)
		s5Ob='0'*(4-len("{0:b}".format(s5O)))+"{0:b}".format(s5O)
		s6Ob='0'*(4-len("{0:b}".format(s6O)))+"{0:b}".format(s6O)
		s7Ob='0'*(4-len("{0:b}".format(s7O)))+"{0:b}".format(s7O)
		s8Ob='0'*(4-len("{0:b}".format(s8O)))+"{0:b}".format(s8O)
		SOO=s1Ob+s2Ob+s3Ob+s4Ob+s5Ob+s6Ob+s7Ob+s8Ob
		for i in range(0,32):
			SO[i]=ord(SOO[i])-ord('0')
		SOP=bitarray(32)
		for i in range(0,32):
			SOP[i]=SO[perm[i]-1]
		for i in range(0,32):
			SOP[i]=SOP[i]^Lhalf[i]
		Lhalf=Rhalf
		Rhalf=SOP
		
	sBoxes = [s1, s2, s3, s4, s5, s6, s7, s8]
	CiTP=bitarray(64)
	CiTPP=Rhalf+Lhalf
	for i in range(0,64):
		CiTP[i]=CiTPP[ipinv[i]-1]	
	word=""
	for i in range(0,64,4):
		temp=changeit(CiTP[i:i+4])
		word=word+temp
	if word==out:
		print(op)
		break
