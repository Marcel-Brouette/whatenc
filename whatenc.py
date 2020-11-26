#!/usr/bin/python3

import re
import json
import argparse
import codecs
import sys
import select
import xml.etree.ElementTree as ET
import gzip
import fingerprint
from datetime import datetime


#### TODO : 
# java/php/python/ruby/asp serialize object
# BSON

TYPE_INT = "INT"
TYPE_FLOAT = "FLOAT"
TYPE_UTF8 = "UTF8"
TYPE_BIN = "BIN"

FTYPE_JSON = "JSON"
FTYPE_XML = "XML"
FTYPE_HTML = "HTML"
FTYPE_TIME = "TIMESTAMP"

TRANSFORMATIONS = {
    TYPE_INT   : ["hex_codec"],
    TYPE_FLOAT : [],
    TYPE_UTF8  : ["rot_13", "base64_codec", "hex_codec"],
    TYPE_BIN   : ["zlib_codec", "bz2_codec", "gzip"]
}

FINAL_TYPE = {
    TYPE_INT   : [FTYPE_TIME],
    TYPE_FLOAT : [FTYPE_TIME],
    TYPE_UTF8  : [FTYPE_JSON, FTYPE_XML],
    TYPE_BIN   : [],
    FTYPE_XML  : [FTYPE_HTML]
}

current_year = datetime.now().year

##########################################################
############################# UTIL #######################


def str2bytes(data): 
    if isinstance(data, str):
        return bytes(data, 'utf_8')
    elif isinstance(data, bytes):
        return data
    else: 
        raise ValueError("Argument must be string or bytes")

def bytes2Str(data):
    try:
        if isinstance(data, str) : 
            return data
        else : 
            return data.decode('utf_8')
    except UnicodeDecodeError:
        return False

def isDelimitedString(string):
    for x in string:
        if x.lower() in ';?&=/,:-':
            return False
    return True

###########################################
########## PRIMARY TYPE

def isNumeric(string):
    try:
        return float(string)
    except Exception as e:
        return False

def isInt(string):
    try:
        return int(string)
    except Exception as e:
        return False

def primitiveType(data): 
    data_str = bytes2Str(data)
    if not data_str : 
        return TYPE_BIN
    if isInt(data_str) : 
        return TYPE_INT
    if isNumeric(data_str): 
        return TYPE_FLOAT
    return TYPE_UTF8

###########################################
########## FINAL TYPE

def isHtml(string): 
    '''
        only call it when you make sure data is xml
    '''
    if "<html" in string: 
        return string
    else : 
        return False


def isXml(string): 
    try:
        xml = ET.fromstring(string)
        return string
    except Exception as e:
        return False

def isJson(string): 
    try:
        xml = json.loads(string)
        return string
    except Exception as e:
        return False

def isTimestamp(numeric): 
    try:
        date = datetime.fromtimestamp(float(numeric))
        if date.year > current_year - 40 and date.year < current_year + 40: 
            return str(date)
        else : 
            return False
    except Exception as e:
        return False


FTYPE_CUSTOM_FUNC = {
    FTYPE_JSON     : isJson,
    FTYPE_XML      : isXml,
    FTYPE_HTML     : isHtml, 
    FTYPE_TIME     : isTimestamp, 
}

###########################################
########## TRANSFORMATION

list_codec = ["rot_13", "base64_codec", "hex_codec", "quopri_codec", "zlib_codec", "bz2_codec"]
txt_codec = ["ascii", "latin_1", "utf_8", "shift_jis", "gbk", "utf_16", "utf_7", "utf_32", "uu_codec"]

def gunzip(data):
    try:
        data_bytes = str2bytes(data)
        return gzip.decompress(data_bytes)
    except Exception as e:
        return False
    

TRANS_CUSTOM_FUNC = {
    "gzip"      : gunzip
}


def try_decode(data, list_enc, last_transforms):
    encoded = {}
    rev_enc = ["rot_13"]
    last_enc = last_transforms.split('|')[-1:][0]
    data_str   = bytes2Str(data)
    data_bytes = str2bytes(data)

    for enc in list_enc : 
        is_dec = True
        if enc in TRANS_CUSTOM_FUNC.keys():
            fn_enc = TRANS_CUSTOM_FUNC[enc]
            dec_data = fn_enc(data)
            if not dec_data: 
                is_dec = False
        elif enc in list_codec and (enc != last_enc or enc not in rev_enc) :
            try : 
                dec_data = codecs.decode(data_bytes, enc)
            except TypeError as e: 
                dec_data = codecs.decode(data_str, enc)
            except Exception as e :
                is_dec = False
        else: 
            is_dec = False

        if is_dec and dec_data != data and dec_data != data_bytes: 
            encoded['%s|%s'%(last_transforms, enc.replace('_codec', ''))] = dec_data 
    return encoded


def transform(data):
    final_result = {}
    this_result = {}
    last_result = {}
    loop_result = {'input': data}
    while len(loop_result) > 0: 
        last_result = loop_result
        loop_result = {}
        for transformation, value in last_result.items():
            ptype = primitiveType(value)
            #print(f'#### {transformation}')
            if ptype in [TYPE_INT, TYPE_FLOAT]:#, TYPE_UTF8]: 
                final_result[transformation] = (value,ptype)
            this_result = try_decode(value, TRANSFORMATIONS[ptype], transformation)
            if not this_result : 
                # rot_13 is not relevent for last transformation
                if transformation.endswith("rot_13") : 
                    transformation = "|".join(transformation.split("|")[:-1]) # drop last rot_13
                    value = codecs.decode(value, "rot_13")
                final_result[transformation] = (value,ptype)
            loop_result.update(this_result)

    return final_result


def pipe2fnStr(transformation, dtype):
    t = transformation.replace('input|', '') 
    t = transformation.replace('input', '') 
    t = f'({dtype})|' + "|".join(t.split('|')[::-1])
    t = t[:-1]

    return t

###########################################
########## DETECTION

def tryDecodeType(ptype, value): 
    final_ptype = ptype
    end_loop = False
    while final_ptype in FINAL_TYPE.keys() and not end_loop: 
        ptype = final_ptype
        for candidate_type in FINAL_TYPE[final_ptype]:
             if FTYPE_CUSTOM_FUNC[candidate_type](value): 
                final_ptype = candidate_type
                break # we assume it can be only one type right now
        end_loop = final_ptype == ptype
    return final_ptype

def fingerPrintType(ptype, value): 
    return fingerprint.match(ptype, str2bytes(value))

def finalType(ptype, value): 
    # Check for fingerprint : 
    final_type = fingerPrintType(ptype, value)
    if not final_type: 
        final_type = tryDecodeType(ptype, value)

    return final_type


def filter_data(data, transform_result): 
    #print(transform_result)
    filtered = []
    for transformation, result in transform_result.items(): 
        value, ptype = result
        final_ptype = finalType(ptype, value)
        if final_ptype != TYPE_BIN: 
            filtered.append((transformation, final_ptype, value))

    if not filtered :
        ptype = primitiveType(data) 
        filtered.append(("input", ptype, data))

    return filtered

def magic(data): 
    transformations = transform(data)
    results = filter_data(data, transformations)
    return results
    for transformation, dtype, value in results: 
        print(pipe2fnStr(transformation, dtype, value))

######################################################
################# MAIN ROUTINE 
######################################################

def print_decoded_values(): 
    sys.stderr.write(f"[*] {len(words)} base words\n")

def display_result(data): 
    print()
    #print(f"--- DATA : {data}")
    magic(data)

def isStdinData(): 
    return select.select([sys.stdin,],[],[],0.0)[0]; 

def main(): 

    stdin_mode = isStdinData()
    parser = argparse.ArgumentParser(description='Find how a data could have been encoded and the nature of the decoded data', add_help=True)
    parser.add_argument('-d'  , action="store_true", dest="decode", default=False, help='display only the decoded data')
    parser.add_argument('-m'  , action="store_true", dest="method", default=False, help='display only the encoding methods')
    if not stdin_mode: 
        parser.add_argument('DATA', help='data to decode, can be pass through pipe')
    args = parser.parse_args()

    input_data = ''
    if stdin_mode : 
        input_data = sys.stdin.read().strip()
    else : 
        input_data = args.DATA

    results = magic(input_data)
    len_res = len(results)
    msg     = f"####### {len_res} possible encoding method : \n"
    if args.decode : 
        msg = f"####### {len_res} possible decoded data : \n"
    if len_res > 1:
        sys.stderr.write(msg)
    sys.stderr.write("\n")
    for transformation, dtype, value in results: 
        if args.method :
            print(f'    - {pipe2fnStr(transformation, dtype)}')
        elif args.decode :
            print(f'{value}')
        else :
            print(f'    - {pipe2fnStr(transformation, dtype)}  =>  {value}')
    sys.stderr.write("\n")


if __name__ == '__main__':
    main()








