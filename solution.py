from socket import *
import os
import sys
import struct
import time
import select
import binascii
import ipaddress

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1
# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def checksum(string):
# In this function we make the checksum of our packet
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
    #Fill in start
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.

    # Make the header in a similar way to the ping exercise.
    # Append checksum to the header.

    # Don’t send the packet yet , just return the final packet in this function.

    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    pId = os.getpid() & 0xFFFF
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, pId, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header

    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)


    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, pId, 1)
    #Fill in end

    # So the function ending should look like this

    packet = header + data
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT
    # tracelist1 = [] #This is your list to use when iterating through each trace 
    tracelist2 = [] #This is your list to contain all traces

    for ttl in range(1,MAX_HOPS):
        tracelist1 = [] #This is your list to use when iterating through each trace 
        for tries in range(TRIES):
            destAddr = gethostbyname(hostname)

            #Fill in start
            # Make a raw socket named mySocket
            icmp = getprotobyname("icmp")
            mySocket = socket(AF_INET, SOCK_RAW, icmp)
            #Fill in end

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t= time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []: # Timeout
                    tracelist1.append(str(ttl))   # hop number
                    tracelist1.append("*")          # rtt
                    tracelist1.append("Request timed out") # host ip and name
                    #Fill in start
                    #You should add the list above to your all traces list
                    tracelist2.append(tracelist1)
                    continue
                    #Fill in end
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    tracelist1.append(str(ttl))   # hop number
                    tracelist1.append("*")          # rtt
                    tracelist1.append("Request timed out") # host ip and name
                    #Fill in start
                    #You should add the list above to your all traces list
                    tracelist2.append(tracelist1)
                    continue
                    #Fill in end
            except timeout:
                continue

            else:
                #Fill in start
                #Fetch the icmp type from the IP packet
                ip_header = recvPacket[0: 20]
                icmp_header = recvPacket[20:28]
                version_header_length, type_of_service, datagram_length, identifier, flags_and_offset, return_ttl, upper_protocol, header_checksum, rtr_ip, dest_ip = struct.unpack("!bbhhhbbhii", ip_header)
                # print("ip header:" + str(ip_header))
                # print("icmp header:" + str(icmp_header))
                # print(rtr_ip)
                if rtr_ip < 0:
                    rtr_ip = rtr_ip + 2**32
                # print(rtr_ip)
                router_ip = ipaddress.ip_address(rtr_ip).__str__()
                # router_ip = '.'.join([str(rtr_ip >> (i << 3) & 0xFF) for i in range(4)[::-1]])
                # print((int)(ipaddress.ip_address(router_ip)))
                types, code, checksum, p_id, sequence = struct.unpack("bbHHh", icmp_header)
                #Fill in end
                try: #try to fetch the hostname
                    #Fill in start
                    routername, routernames1, routernames2 = gethostbyaddr(router_ip)
                    # print("hostname: " + routername)
                    #Fill in end
                except herror:   #if the host does not provide a hostname
                    #Fill in start
                    routername = "hostname not returnable"
                    #Fill in end
                except gaierror:
                    print("error here!")
                    routername = "hostname not returnable"

                timeSent = timeReceived
                if types == 11:
                    bytes = struct.calcsize("d")
                    # timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # print("timeSent: " + str(timeSent) + ", timeStarted: " + str(startedSelect))
                    delay = round(((1000*(timeSent - startedSelect))/2), 2)
                    #Fill in start
                    #You should add your responses to your lists here
                    tracelist1.append(str(ttl))   # hop number
                    tracelist1.append(str(delay)+"ms")          # rtt
                    tracelist1.append(router_ip)    # host ip
                    tracelist1.append(routername)   # hostname
                    # print(tracelist1)
                    tracelist2.append(tracelist1)
                    continue
                    #Fill in end
                elif types == 3:
                    bytes = struct.calcsize("d")
                    # timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # print("timeSent: " + str(timeSent) + ", timeStarted: " + str(startedSelect))
                    delay = round(((1000*(timeSent - startedSelect))/2), 2)
                    #Fill in start
                    #You should add your responses to your lists here 
                    tracelist1.append(str(ttl))   # hop number
                    tracelist1.append(str(delay)+"ms")          # rtt
                    tracelist1.append(router_ip)    # host ip
                    tracelist1.append("destination unreachable")   # hostname                    
                    # print(tracelist1)
                    tracelist2.append(tracelist1)
                    continue
                #Fill in end
                elif types == 0:
                    bytes = struct.calcsize("d")
                    # timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # print("timeSent: " + str(timeSent) + ", timeStarted: " + str(startedSelect))
                    delay = round(((1000*(timeSent - startedSelect))/2), 2)
                    #Fill in start
                    #You should add your responses to your lists here and return your list if your destination IP is met
                    tracelist1.append(str(ttl))   # hop number
                    tracelist1.append(str(delay)+"ms")          # rtt
                    tracelist1.append(router_ip)    # host ip
                    tracelist1.append("final destination: " + routername)   # hostname
                    # print(tracelist1)
                    tracelist2.append(tracelist1)
                    print(tracelist2)
                    return tracelist2
                    #Fill in end
                else:
                    #Fill in start
                    #If there is an exception/error to your if statements, you should append that to your list here
                    tracelist1.append(str(ttl))   # hop number
                    tracelist1.append("*")          # rtt
                    tracelist1.append(router_ip)    # host ip
                    tracelist1.append(routername)   # hostname
                    # print(tracelist1)
                    tracelist2.append(tracelist1)
                    continue
                    #Fill in end
                break
            finally:
                mySocket.close()

if __name__ == '__main__':
    get_route("google.co.il")