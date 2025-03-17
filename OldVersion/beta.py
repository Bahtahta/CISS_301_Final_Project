# Author: Blake R. Marshall
# Date of creation 2/21/2025

# Overview of file:
#   This file will create and use a small database like structure that could be ever expanding
#   This will scan a file and potentially update that database while analyzing a file and giving it a score based off
#   of how dangerous the file could be. The more the program is fed, the better it will be at identyfing threats

import os
import json
import hashlib
import re
from collections import Counter
import base64 as ba

# Pseudo-database file
DBFILE = "malwareDb.json"
OBFUSCATIONKEY = 7  # Simple Caesar cipher for obfuscation

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
    with open(filePath, 'r', errors='ignore') as f:
        content = f.read()
    return tokenizeText(content)


# Uses the Jaccard Similarity to calculate the distance between two words
# more informaton of Jaccard similarity here :
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
    if not os.path.exists(DBFILE):
        return {}
    with open(DBFILE, 'r') as f:
        data = json.load(f)
    return {deobfuscateText(k): set(v) for k, v in data.items()}


# Saves the sudo database infromation with obfuscated text
def saveDatabase(db):
    obfuscatedDb = {obfuscateText(k): list(v) for k, v in db.items()}
    with open(DBFILE, 'w') as f:
        json.dump(obfuscatedDb, f, indent=2)


# Updates the sudo Database by storing the bag-of-words structure
# This is identified by the hash of the file
def updateDatabase(filePath, bag):
    db = loadDatabase()
    fileHash = hashFile(filePath)
    db[fileHash] = bag
    saveDatabase(db)


# Compares the files using Jaccard Similarity. there isnt too much to say
# on this. its about as strait forward as it gets
# This will not give a malware score and is purely to update the database
def compareFiles(file1, file2):
    bag1, bag2 = extractBagOfWords(file1), extractBagOfWords(file2)
    similarity = jaccardSimilarity(bag1, bag2)
    print(f"Jaccard Similarity: {similarity:.4f}")
    updateDatabase(file1, bag1)
    updateDatabase(file2, bag2)


# Compares a the database with a file. this will not update the database
# This will sue the Jaccard Similarity and give back the malware rating based on the
# current database
# If there is no match, it will be considered a low risk
def compareWithDatabase(file):
    db = loadDatabase()
    bag = extractBagOfWords(file)
    fileHash = hashFile(file)

    if fileHash in db:
        print("File already exists in the database.")
        return

    scores = {hashKey: jaccardSimilarity(bag, db[hashKey]) for hashKey in db}
    bestMatch = max(scores, key=scores.get, default=None)

    if bestMatch:
        similarity = scores[bestMatch]
        score = calculateMalwareScore(similarity)
        print(f"Malware Score (1-10): {score}")
    else:
        print("Malware Score: 1 (lowest risk)")
        

# This will force an update of the database to add new files one at a time
def forceUpdate(file):
    bag = extractBagOfWords(file)
    updateDatabase(file, bag)
    print(f"Updated Database!")


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
    if len(sys.argv) == 3:
        compareFiles(sys.argv[1], sys.argv[2])
    elif len(sys.argv) == 2:
        if sys.argv[1].lower() == "rustlethecrow":
            arbiter()
        else:
            compareWithDatabase(sys.argv[1])
    elif len(sys.argv) == 3 and sys.argv[1].lower() == "update" :
        forceUpdate(sys.argv[2])
    else:
        print("Usage: python beta.py (file1) (file2)")
        print("       py beta.py update (file)")
        
        
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
