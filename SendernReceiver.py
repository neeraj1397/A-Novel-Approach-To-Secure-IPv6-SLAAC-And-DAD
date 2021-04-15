import hashlib
import random
import calendar
import time
import timeit

cc=0                                                  #Collision count for Neighbour Advertisements
NS_cc=0                                               #Collision count for Neighbour Solicitations
Uf=False                                              #Uniqueness flag
IID="0"                                               #Initializa Interface Identifier
prefix=input("Enter Network Prefix in binary: ")
GUA="0"                                               #Initialize Global Unicast Address
TPIID="0"                                             #Target Interface Identifier for Neighbour Solicitation
T_IP="0"                                              #Target IP address for Neighbour Solicitation

# Address generation code
def addr():
	global cc, NS_cc, Uf, IID, prefix, GUA, TPIID, T_IP
	Rn=random.randint(0, 2**64)
	ts=calendar.timegm(time.gmtime())                 # Get the current timestamp
	Ts="{0:b}".format(ts)                             # Converting timestamp into binary
	Rn="{0:b}".format(Rn)
	CRn="{0:b}".format(cc)+"{0:b}".format(NS_cc)+Ts+Rn
	output1=hashlib.sha1(CRn.encode())                # Applying SHA-1 hash on CRn 
	output1=output1.hexdigest()                       # Converting the hash into hexadecimal form
	output1 = "{0:08b}".format(int(output1, 16))      # Converting the hash into binary
	sub1=output1[0:80]                                # Split hash-1 into two equal parts
	sub2=output1[80:160]
	IID=sub1[0:25]+sub2[0:25]+Rn[0:14]                # Construct the interface identifier of the device
	GUA=prefix+IID                                    # Construct the GUA of the device
	output2=hashlib.sha512(IID.encode())              # Apply SHA-512 on generated hash-1
	output2=output2.hexdigest()
	output2 = "{0:08b}".format(int(output2, 16))      # Converting hash-2 into binary
	TPIID=output2[0:40]+GUA[104:128]                  # Construct the interface identifier for neighbour Solicitation
	T_IP=prefix+TPIID                                 # Construct the IP address for neighbour Solicitation
	print("Generated GUA:",GUA)
	print("GUA to be placed in the target address field of ICMP header:",T_IP)


# Sender Code
start = timeit.timeit()
addr()
end = timeit.timeit()
print("Address generation time:",end-start,"seconds") # Calculate the address generation time for evaluation


# DAD begins
while(True):
	NA_Flag=int(input("Is NA received?.. True-1 or False-0: "))
	if NA_Flag==1:
		print(GUA)
		R_GUA=input("Enter GUA from received ICMPv6 header: ")
		if R_GUA==GUA:
			cc=cc+1
			if cc==5:
				print("Malicious activity detected!! Retaining the generated address.")
				Uf=True
				break
			else:
				addr()
		else:
			Uf=True
			print("Generated GUA is unique.")
			break
	else:
		Uf=True
		print("No NA received.")
		print("Generated GUA is unique.")
		break


while(True):
	NS_Flag=int(input("Is NS for same address received?.. True-1 or False-0: "))
	if NS_Flag==1:
		NS_cc=NS_cc+1
		if NS_cc==5:
			print("Malicious activity detected!! Retaining the generated address.")
			Uf=True
			break
		else: 
			addr()
	else:
		print("No NS received.")
		Uf=True
		break


# Receiver Code
rcvr=int(input("Do you want to run the receiver code?.. True-1 or False-0: "))
if rcvr==1:
	RTIP=input("Enter the target IPv6 address field in the Received ICMP header of Neighbor Solicitation: ")
	RTIID=RTIP[65:128]
	if TPIID==RTIID:
		print("Address matched!! Sending neighbour advertisement...")
	else:
		print("Address not matched. Discarding neighbour solicitation...")

#1111111010000000000000000000000000000000000000000000000000000000