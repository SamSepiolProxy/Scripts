#!/usr/bin/python
import sys
import argparse
import os
import ntpath

def get_args():
    parser = argparse.ArgumentParser(description='XOR Encryptor')
    parser.add_argument('-i', dest='filename', type=str, required=True, help='Input File')
    parser.add_argument('-o', dest='fileout', type=str, required=False, help='Output File')
    parser.add_argument('-k', dest='key', type=str, required=True, help='Key')
    return parser.parse_args()

def readfile(filename):
    with open(filename, 'rb') as f:            
        contents = f.read()
    return contents


def xorcrypt(data, key):
    no_of_itr = len(data)
    result = ""
    for i in range(no_of_itr):
        current = data[i]
        current_key = key[i%len(key)]
        result += chr(current ^ ord(current_key))     
    return bytes(result, encoding='utf-8')

if __name__ == '__main__':
    args = get_args()

    data = readfile(args.filename)

    dataxor = xorcrypt(data, args.key)


    if args.fileout is None:  
     head,tail = ntpath.split(args.filename)
     sc_filename = tail.split('.')[0]+'.xor'
    else:
     sc_filename = args.fileout

	 
    sc_filepath = os.path.join(os.getcwd(),sc_filename)
    fileb = open(sc_filepath,'wb')
    fileb.write(dataxor)
    fileb.close()

    print(f"[+] XOR version is written to:\n    {sc_filepath}")
