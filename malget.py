# Malget by Droogy
#
# Your own personal malware feed!
#
import shutil

from apiCreds import MALSHAREKEY, VTKEY
import os
import requests
import json
from time import sleep
from pprint import pprint
import argparse
import sys
import concurrent.futures

args = None
total_downloaded = 0
download_dir = 'download'
# dictionary storing our magic bytes and associated filetype
magicTypes = {"pe" :b'\x4d\x5a\x90\x00',
              "elf":b'\x7f\x45\x4c\x46',
              "zip":b'\x50\x4b\x03\x04'}
sha1hashes = None
malware_folders = ["pe", "elf", "zip", "misc"]

def create_dir():
    '''
    Check if we have directories to hold the samples
    and their subsequent categories
    '''
    # handle the "FileExistsError" if the dir exists
    [os.mkdir(dir) for dir in malware_folders if not os.path.exists(dir)]

def grab_hashes():
    '''
    query Malshare for ALL samples from last 24h
    '''
    # initialize sha1hashes which contains ALL hashes from last 24 hrs
    global sha1hashes
    payload = {"api_key":MALSHAREKEY, "action":"getlist"}
    r = requests.get("https://malshare.com/api.php", params=payload)
    raw_hashlist = r.text
    pprint(raw_hashlist)
    loadedJSON = json.loads(raw_hashlist)
    sha1hashes = [hash["sha1"] for hash in loadedJSON]

def download_samples():
    '''
    download specified amount of samples we just queried from Malshare
    '''
    global total_downloaded
    
    print(f'[i] downloading examples ...')
    for hash in sha1hashes[:args.number]:
        payload = {"api_key":MALSHAREKEY, "action":"getfile", "hash":hash}
        r = requests.get("https://malshare.com/api.php", params=payload)
        sample = r.content
        total_downloaded += 1
        try:
            os.mkdir(download_dir)
        except:
            pass
        with open(os.path.join(download_dir, hash), "wb") as fh:
            print(f"[d] download {hash} #{total_downloaded:-4d}")
            fh.write(sample)

def first_bytes(file2read, n_bytes=4):
    '''
    Returns first four hex-encoded bytes of a file
    '''
    with open(file2read, "rb") as fd:
        return fd.read(n_bytes)

def get_key(invalue):
    '''
    Returns a key when given a dictionary value
    '''
    for key, value in magicTypes.items():
        if invalue == value:
            return key

def query_vt(sampleHash):
    '''
    query VT to see if we can get names for each sha1 hash passed to this function
    '''
    header = {"x-apikey":VTKEY}
    url = f"https://www.virustotal.com/api/v3/files/{sampleHash}"
    vtRequest = requests.get(url, headers=header)
    JSONData = vtRequest.json()
    try:
        print(f'[i] {JSONData["data"]["attributes"]["type_description"]}')
    except:
        print(f'<unknown> {JSONData}')
    JSONArray.append(JSONData)

def rename_samples():
    '''
    rename the samples if we found anything on VT
    '''
    files = sha1hashes[:args.number]
    for file in files:
        for fileQuery in JSONArray:
            try:
                if str(file) == fileQuery["data"]["attributes"]["sha1"]:
                    fileName = fileQuery["data"]["attributes"]["meaningful_name"]
                    print(f"[i] {file} identify: {fileName} ")
                    dest_path = os.path.join(download_dir, fileName)
                    shutil.move(os.path.join(download_dir, file), f"{dest_path}")
            except Exception as e:
                continue

def classify_samples():
    '''
    classify the files based on their filetype and move them
    to their respective folder
    '''
    # make a list containing ONLY files from current directory
    print(f'[i] classifying examples ...')
    files = list(os.listdir(download_dir))
    for file in files:
        file_path = os.path.join(download_dir, file)
        try:
            if first_bytes(file_path) in magicTypes.values():
                print(f"[c] {file} type:{get_key(first_bytes(file_path))}")
                os.replace(f"{file_path}", f"{get_key(first_bytes(file_path))}/{file}")
            else:
                print(f"[!] {file} unidentified")
                os.replace(f"{file_path}", f"misc/{file}")
        except Exception as e:
            print(f'classify: {e}')
            continue

if __name__ == '__main__':
    global parser
    global JSONArray
    # all of our VT data will be stored in this array, memory be damned!
    JSONArray = []
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--number", type=int, default=1110, help="number of samples to download")
    args = parser.parse_args()
    if args.number:
        print(f"[*] Creating directory structure for {args.number} malware")
        create_dir()
        print("[*] Grabbing list of hashes from Malshare")
        grab_hashes()
        print("[*] Looking up these hashes on VirusTotal")
        
        # slice the global variable "sha1hashes" to grab specified number
        for hash in sha1hashes[:args.number]:
            print(f'[i] queryng {hash}')
            query_vt(hash)
            sleep(.5)  # sleep to abide by VT's 4/min requests API cap
        
        # debugging print statement to make sure hashes are correct
        # print(f"Printing the hashes we found:\n{sha1hashes[:args.number]}")
        download_samples()
        rename_samples()
        classify_samples()
        
        with open("VTResults.json", "w") as outfile:
            json.dump(JSONArray, outfile)
        
        with open("sampleHashes.txt", "w") as outfile:
            outfile.write(str(sha1hashes[:args.number]))
    
    elif len(sys.argv) <= 1:
        print("Add --help for usage")
