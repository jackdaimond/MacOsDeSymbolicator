#!/usr/bin/env python3

import glob
import os
import re
import subprocess

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
#threadLineRegEx = re.compile("(\\d+)\\s+(\\S\\.*)\\s+(0x[A-Za-z0-9]*)\\s+(\\S+)")
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

def scanCrashReport(crashReport):
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

        m = threadBeginRegEx.match(l)
        if m:
            inThread = True
        elif inThread:
            m = threadLineRegEx.match(l)
            if m:
                pl = processLine(m.group(2).strip(), arch, m.group(3))
                s = l
                if len(pl) > 0:
                    s = s + " -> " + pl
                line = s
        print(line)

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
        item.BundleIdentifier = binaryOptions[0].replace("com.apple.xcode.dsym.", "") #com.apple.xcode.dsym.com.zynaptiq.triumph3
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

#binaryImagesRegEx = re.compile("^\\s*(0x[A-Fa-f0-9]*)\s*-\s*0x[A-Fa-f0-9]*")
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

            #scan line
            #check if DSYM is available
                #scan DSYM for: Binary, store item with:
                # DSYM-path, DSYMBinary, load address
                # binaryAddressDict[DSYMBinary] = item


crashFile = "/private/tmp/bla/20231219.101345_Zynaptiq_Mac_Audio_Applications_Pace_With-ARM11Support_212_notarized/20231219.101345_Zynaptiq_Mac_Audio_Applications_Pace_With-ARM11Support_212_notarized/myriad.crash"
crashFile = "/Users/michaelkloske/Desktop/Triumph Crash/Crash.txt"

dSyms = scanDSyms("/Users/michaelkloske/Desktop/Triumph Crash/")
scanBinaryImages(crashFile, dSyms)

binAddressDict = dSyms

def initDebug():
    #"/Users/michaelkloske/Desktop/Triumph Crash/Crash.txt"
    item = AddressItem()
    item.DSym = "/Users/michaelkloske/Desktop/Triumph Crash/Zynaptiq TRIUMPH 3.app.dSYM"
    item.DSymBinary = "Zynaptiq TRIUMPH 3"
    item.LoadAddress = "0x103f30000"

    binAddressDict["Zynaptiq TRIUMPH 3"] = item

    item = AddressItem()
    item.DSym = "/private/tmp/bla/20231219.101345_Zynaptiq_Mac_Audio_Applications_Pace_With-ARM11Support_212_notarized/20231219.101345_Zynaptiq_Mac_Audio_Applications_Pace_With-ARM11Support_212_notarized/DSYM/Myriad/Zynaptiq MYRIAD 4.app.dSYM"
    item.DSymBinary = "Zynaptiq MYRIAD 4"
    item.LoadAddress = "0x100484000"
    binAddressDict["Zynaptiq MYRIAD 4"] = item

    item = AddressItem()
    item.DSym = "/private/tmp/bla/20231219.101345_Zynaptiq_Mac_Audio_Applications_Pace_With-ARM11Support_212_notarized/20231219.101345_Zynaptiq_Mac_Audio_Applications_Pace_With-ARM11Support_212_notarized/DSYM/Myriad/AFECore.framework.dSYM"
    item.DSymBinary = "AFECore"
    item.LoadAddress = "0x100f88000"
    binAddressDict["AFECore"] = item

#crashFile = "/Users/michaelkloske/Desktop/Triumph Crash/Crash.txt"

scanCrashReport(crashFile)