#!/usr/bin/env python3

import argparse
import glob
import os
import re
import subprocess
import sys

class AddressItem:
    def __init__(self):
        self.DSym = ""
        self.DSymBinary = ""
        self.DSymBinaryFilePath = ""
        self.DSymVersion = ""
        self.LoadAddress = ""
        self.BundleIdentifier = ""

    def update(self):
        if len(self.DSymBinaryFilePath) == 0 and self.DSym != None and self.DSymBinary != None:
            self.DSymBinaryFilePath = os.path.join(self.DSym, f"/Contents/Resources/DWARF/{item.DSymBinary}")


binAddressDict = {}
archDecodeDict = {"ARM-64" : "arm64", "X86-64" : "x86_64"}

threadBeginRegEx = re.compile("^\s*Thread (\d*)")
threadLineRegEx = re.compile("^\\s*(\\d*)\\s*(.*)\\s+(0x[A-Fa-f0-9]+) (.*\\s\\+\\s\\d*)")
archTypeRegEx = re.compile("^\\s*Code Type\\:\\s*([A-Za-z0-9-_]*)")

def getStrippedOutputFromCall(cmdLine, addEmptyLines = False):
    p = subprocess.Popen(cmdLine, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    res = []
    for line in p.stdout.readlines():
        l = str(line)
        l = l.strip()
        if len(l) > 0 or addEmptyLines:
            res.append(l)
    return res

#arch = "arm64" #"x86_64"
def processLine(binary, arch, address):
    if binary in binAddressDict:
        item = binAddressDict[binary]
        
        #atos -arch <BinaryArchitecture> -o <PathToDSYMFile>/Contents/Resources/DWARF/<BinaryName>  -l <LoadAddress> <AddressesToSymbolicate>
        cmdLine = f"atos -arch {arch} -o \"{item.DSymBinaryFilePath}\" -l {item.LoadAddress} {address}"
        #execute cmdLine and return the output
        output = getStrippedOutputFromCall(cmdLine)
        
        res = ""
        for line in output:
            if len(res) > 0:
                res = res + " "
            res = res + line
        return res
    return ""

def scanCrashReport(crashReport, outputFile):
    file = open(crashReport)
    inThread = False
    arch = ""
    for l in file:
        l = l.rstrip()
        line = l
        if len(arch) == 0:
            m = archTypeRegEx.match(l)
            if m:
                arch = archDecodeDict[m.group(1)]
            if len(arch) > 0:
                inThread = True
        elif inThread:
            if l.strip().startswith("Binary Images:"):
                inThread = False
            else:
                m = threadLineRegEx.match(l)
                if m:
                    pl = processLine(m.group(2).strip(), arch, m.group(3))
                    s = l
                    if len(pl) > 0:
                        s = s + " -> " + pl
                    line = s
        print(line, file=outputFile)

def scanDSym(dsymPath):
    binaryFile = None
    binaryOptions = []

    #1. find binary
    binaryFilter = os.path.join(dsymPath, "Contents/Resources/DWARF/*")
    binaries = glob.glob(binaryFilter)
    if binaries != None and len(binaries) == 1:
        binaryFile = binaries[0]

    #2. get id
    plistFile = os.path.join(dsymPath, "Contents/Info.plist")
    identifiers = ["CFBundleIdentifier", "CFBundleShortVersionString"]
    for identifier in identifiers:
        cmdLine = f"/usr/libexec/PlistBuddy -c \"Print :{identifier}\" \"{plistFile}\""
        output = getStrippedOutputFromCall(cmdLine)
        if output != None and len(output) == 1:
            binaryOptions.append(output[0])

    if binaryFile != None and len(binaryOptions) > 0:
        item = AddressItem()
        item.DSym = dsymPath
        item.DSymBinary = os.path.basename(binaryFile)
        item.DSymBinaryFilePath = binaryFile
        item.BundleIdentifier = binaryOptions[0].replace("com.apple.xcode.dsym.", "")
        item.DSymVersion = binaryOptions[1]

        return item
    return None


def scanDSyms(basepath):
    p = os.path.join(basepath, "*.dSYM")
    dSYMDirs = glob.glob(p)

    dSyms = {}

    for dSYM in dSYMDirs:
        item = scanDSym(dSYM)
        if item != None:
            dSyms[item.DSymBinary] = item
    return dSyms

binaryImagesRegEx = re.compile("^\\s*(0x[A-Fa-f0-9]*)\\s*-\\s*0x[A-Fa-f0-9]*\\s+((?:\\w|\\.)*)\\s+(\\(.*\\))")

def findDSymByBundleIdentifier(dSyms, bundleIdentifier):
    for dSymBundleId in dSyms:
        dSym = dSyms[dSymBundleId]
        if dSym.BundleIdentifier == bundleIdentifier:
            return dSym
    return None


def scanBinaryImages(crashReport, dSyms):
    file = open(crashReport)
    isInBinaryImages = False
    foundDSyms = 0
    for l in file:
        if l.strip().startswith("Binary Images:"):
            isInBinaryImages = True
        elif isInBinaryImages:
            m = binaryImagesRegEx.match(l)
            if m:
                binaryLoadAddress = m.group(1)
                binaryId = m.group(2)
                binaryVersion = m.group(3)

                dSym = findDSymByBundleIdentifier(dSyms, binaryId)
                if dSym != None:
                    dSym.LoadAddress = binaryLoadAddress
                    foundDSyms = foundDSyms + 1
                    if foundDSyms == len(dSyms):
                        return

parser = argparse.ArgumentParser(description = "MacOSX Crash Report Symbolicator")

parser.add_argument("-d", "--dsym_path", action='append', help = "Adds a search path for DSyms.")
parser.add_argument("-o", "--output", metavar='<output>', action="store", help = "Places the symbolicated crash report into <output>.")
parser.add_argument("crashreport", help = "The crash report file that shall be analyzed and symbolicated.")

args = parser.parse_args()
#crashFile = "/private/tmp/Crash/Crash importing Desktop.txt"
crashFile = os.path.abspath(args.crashreport)

if not os.path.isfile(crashFile):
    if not os.path.exists(crashFile):
        print(f"Crash Report '{crashFile}' does not exists.", file=sys.stderr)
    else:
        print(f"Crash Report '{crashFile}' is not a file. Please select a valid Crash Report - text file.", file=sys.stderr)
    exit(1)

# paths to locate DSYMS
#  - next to python program
#  - next to crash report
#  - working directory

def updateUniqueList(l, value):
    if value in l:
        l.remove(value)
    l.append(value)

def findAndScanDSyms(scriptPath, crashFile, additionalSearchPaths = None):
    dSymSearchPaths = []

    if scriptPath == None:
        scriptPath = __file__
    scriptPath = os.path.dirname(os.path.abspath(__file__))

    dSymSearchPaths.append(scriptPath)
    if additionalSearchPaths != None:
        for path in additionalSearchPaths:
            updateUniqueList(dSymSearchPaths, os.path.abspath(path).upper())

    updateUniqueList(dSymSearchPaths, os.path.dirname(os.path.abspath(crashFile)).upper())
    updateUniqueList(dSymSearchPaths, os.getcwd().upper())

    dSyms = {}
    processedPaths = set()

    print("Scan DSYM Paths:", file=sys.stderr)

    for path in dSymSearchPaths:
        if os.path.sep == '\\':
            path = path.upper()
        if path in processedPaths:
            continue
        processedPaths.add(path)

        print(f"    DSYM Path {path}", file=sys.stderr)
        newDSyms = scanDSyms(path)
        if newDSyms != None:
            dSyms.update(newDSyms)

    return dSyms

print(f"Process Crashfile {crashFile}", file=sys.stderr)

dSyms = findAndScanDSyms(None, crashFile, args.dsym_path)

outputFile = sys.stdout
closeOutput = False
if args.output != None:
    path = os.path.abspath(args.output)
    outputFile = open(path, "w")
    closeOutput = True
    print(f"Store symbolicated crash report in {path}")

scanBinaryImages(crashFile, dSyms)
binAddressDict = dSyms
scanCrashReport(crashFile, outputFile)

if closeOutput:
    outputFile.close()
