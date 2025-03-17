# Author: Blake R. Marshall
# Date of creation 2/21/2025

# Overview of file:
#   This file will create and use a small database like structure that could be ever expanding
#   This will scan a file and potentially update that database while analyzing a file and giving it a score based off
#   of how dangerous the file could be. The more the program is fed, the better it will be at identyfing threats

import os
#import json
import sqlite3
import hashlib
import re
import tempfile
from collections import Counter
from pathlib import Path
import base64 as ba

# Pseudo-database file
DBFILE = "malwareDb.sqlite"
OBFUSCATIONKEY = 7  # Simple Caesar cipher for obfuscation

def database():
    connectDB = sqlite3.connect(DBFILE)
    cursor = connectDB.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS MalwareSig
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fileHash TEXT UNIQUE,
                    BoW TEXT)''')
    connectDB.commit()
    connectDB.close()

# Obfuscates the text using the Caesar cipher. As a gravity falls fan, i just wanted to include this
# this Obfucation prevents people from reading the database wthout the key to deciphering it
def obfuscateText(text):
    return "".join(chr(ord(c) + OBFUSCATIONKEY) for c in text)

# Reverses the Obfuscation to reteive the original text to be compared with another file
def deobfuscateText(text):
    return "".join(chr(ord(c) - OBFUSCATIONKEY) for c in text)


# Computes the SHA-256 hash of a file to identify it. this will prevent duplicates
# in case someone adds a file already in my sudo database
# This is maily just to prevent the database from getting flooded with the same information
def hashFile(filePath):
    hasher = hashlib.sha256()
    with open(filePath, 'rb') as f:
        while chunk := f.read(4096):
            hasher.update(chunk)
    return hasher.hexdigest()


# Tokenizes the text using regular expressions and lowering it to extact the values
# This is where the Bag-of-Words part comes into play. it returns the unique set of words for the comparison
def tokenizeText(text):
    text = re.sub(r'[^a-zA-Z0-9_]', ' ', text.lower())
    return set(text.split())


# reads the file and extracts its token information. returns a set of unique words representing whats in the file
def extractBagOfWords(filePath):
    try:
        with open(filePath, 'r', errors='ignore') as f:
            content = f.read()
        return tokenizeText(content)
    except Exception as e:
        print(f"Error reading the file {filePath}: {e}")
        return set()
    
def extractStrings(filePath):
    try:
        with open(filePath, 'rb') as f:
            rawData = f.read()
            
        asciiStrings = set(re.findall(rb'[\x20-\x7E]{4,}', rawData))
        unicodeStrings = set(re.findall(rb'(?:[\x20-\x7E]\x00){4,}', rawData))
         
        asciiDecoded = {s.decode('utf-8', errors='replace') for s in asciiStrings}
        unicodeDecoded = {s.decode('utf-16le', errors='replace') for s in unicodeStrings}
        
        strings = asciiDecoded | unicodeDecoded
        
    except Exception as e:
        print(f"Error extracting strings from {filePath}: {e}")
    
    return strings


def extractPEInfo(filePath):
    try:
        peStrings = extractStrings(filePath)
        tempPath = "extracted_strings.txt"
        with open(tempPath, "w", encoding="utf-8") as tempFile:
            tempFile.write("\n".join(peStrings))
        bagOfWords = extractBagOfWords(tempPath)
        os.remove(tempPath)
        return bagOfWords
    except Exception as e:
        print(f"Error analyzing PE or EXE file {filePath}: {e}")
        return set()    
        
def analyzeFile(filePath):
    ext = filePath.lower().split('.')[-1]
    if ext in ['exe', 'dll']:
        return extractPEInfo(filePath)
    else:
        return extractBagOfWords(filePath)


# Uses the Jaccard Similarity to calculate the distance between two words
# more informaton of Jaccard similarity here : https://users.cs.utah.edu/~jeffp/DMBook/L3-Jaccard+nGram.pdf
# Basically its an equation that returns a value between 0 and 1. 0 being no similarity between them
# and 1 being identical
def jaccardSimilarity(set1, set2):
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    return intersection / union if union else 0


# This was something i wanted to do based on VirusTotal.com. This converts the Jaccard similarity to a score
# Later in the code it breaks in down further, but the higher the malware score / closer the score is to the database
# The more likely its malware
def calculateMalwareScore(similarity):
    return round(similarity * 10)


# Loads the sudo database for the encrypted files. if the database does not exist in the files / it cant find it
# the program will create a new database file
# The one on my GitHub has a database i recommend you download. This contains some malware code I created in the past
def loadDatabase():
    connectDB = sqlite3.connect(DBFILE)
    cursor = connectDB.cursor()
    cursor.execute("SELECT fileHash, BoW FROM MalwareSig")
    db = {row[0]: set(deobfuscateText(row[1]).split()) for row in cursor.fetchall()}
    connectDB.close()
    return db

# Updates the sudo Database by storing the bag-of-words structure
# This is identified by the hash of the file
def updateDatabase(filePath, bag):
    db = loadDatabase()
    fileHash = hashFile(filePath)
    
    if fileHash in db:
        print("File already in database")
        return
    
    
    connectDB = sqlite3.connect(DBFILE)
    cursor = connectDB.cursor()
    cursor.execute("INSERT INTO MalwareSig (fileHash, BoW) VALUES (?, ?)",
                   (fileHash, obfuscateText(" ".join(bag))))
    connectDB.commit()
    connectDB.close()
    print("Database updated successfully!")



# Compares a the database with a file. this will not update the database
# This will sue the Jaccard Similarity and give back the malware rating based on the
# current database
# If there is no match, it will be considered a low risk
def compareWithDatabase(file):
    db = loadDatabase()
    bag = analyzeFile(file)
    fileHash = hashFile(file)
    
    if fileHash in db:
        print("File already in database")
        return
    
    scores = {hashKey: jaccardSimilarity(bag, db[hashKey]) for hashKey in db}
    bestMatch = max(scores, key=scores.get, default=None)
    
    if bestMatch:
        similarity = scores[bestMatch]
        score = calculateMalwareScore(similarity)
        if score == 0:
            score = score + 1
        print(f"Malware Score: {score}")
        
def translateDatabase(num):
    #if not (isinstance(num, int)) or num != "all":
        #print(f"I dont understand the command {num}. please try again.")
        #sys.exit(1)
    connectDB = sqlite3.connect(DBFILE)
    cursor = connectDB.cursor()
    cursor.execute("SELECT BoW FROM MalwareSig")
    if num == "all":
        rows = cursor.fetchall()
    else:
        rows = cursor.fetchmany(num)
        
    connectDB.close()
    
    pattern = re.compile(r"^[a-zA-Z0-9._-]+$")
    count = 0
    for row in rows:
        text = deobfuscateText(row[0])
        words = text.split()
        for word in words:
            if pattern.match(word):
                print(word)
                count += 1
                if isinstance(num, int) and count >= num:
                    return
        

def arbiter():
    a = "ICpcKioKICoqKi0qKgogICAgKioqXCoqCiAgICAgICAqKlwqKl8gICAgICAgX19fCiAgICAgICAvKiotKiotLS0tLS0tICAgXAogICAgICB8X19fX1xfX19fX19fX19fX198CiAgICAgIHxfX19fX19fX19fX19fX19fX3wKIC1fX19fL19fX19fX19fX19fX19fX19fXF9fX18vCiAgICAgLyAgICAgICAgIF9fICAgICAgXAogICAgIHwgICAgICAgIHwgIHwgICAgICB8X18KICAgICB8ICAgICAgICB8X198ICAgICAgICAgIFxfX19fX19fX19fXwogICAgIFwgICAgICAgICAgIF9fX19fXyAgICAgICAgICAgICAgICAgXF8KICAgICAgL3x8fHx8fHx8fFxfX19fX19cX19fX19fX19fX19fX19fX19cfAogICAgICB8fHx8fHx8fHx8fAogSGEgaGEuIFlvdSBmb3VuZCBtZSEgLSBSdXN0eXk="
    b = ba.b64decode(a).decode()
    print(b)

# Finally we get to the main part of the script. I'm sorry i just love functions!
# there are multiple entry points for the script.
# the first one is comparing a file to a file to get the similarity score
# The second is comparing a file to the database
# The third is forcing an update on the database
if __name__ == "__main__":
    import sys
    database()
    if len(sys.argv) == 3:
        command = sys.argv[1].lower()
        argument = sys.argv[2]
        if command == "update" :
            updateDatabase(argument, analyzeFile(argument))
        elif command == "translate":
            if argument.isdigit():
                num = int(argument)
            elif argument.lower() == "all":
                num = "all"
            else:
                print("Unknown command")
            translateDatabase(num)
    elif len(sys.argv) == 2:
        if sys.argv[1].lower() == "rustlethecrow":
            arbiter()
            translateDatabase()
        else:
            compareWithDatabase(sys.argv[1])
    else:
        print("Usage: python Pynalizer.py (file1) (file2)")
        print("       py Pynalizer.py update (file)")
        print("       py Pynalizer.py translate (all/number)")
        
        
# Resources used when writing:
#      https://github.com/CrowdStrike/embersim-databank
#      https://www.crowdstrike.com/en-us/blog/embersim-large-databank-for-similarity-research-in-cybersecurity/
#      https://users.cs.utah.edu/~jeffp/DMBook/L3-Jaccard+nGram.pdf
#      https://users.cs.utah.edu/~jeffp/DMBook/L4-Minhash.pdf
#      https://users.cs.utah.edu/~jeffp/DMBook/L5-LSH.pdf
#      https://www.newscatcherapi.com/blog/ultimate-guide-to-text-similarity-with-python
#        Note: i didnt use the same concepts or code they used, but it was a huge help
#      https://www.base64encode.org/
#      https://docs.python.org/3/library/index.html
#        Note: used for hashlib, base64, re, json
#      Starting out with PYTHON fifth edition by Tony Gaddis