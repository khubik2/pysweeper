#!/usr/bin/python3

# You need to install these packages:
# tk, pycryptodome, pyserial

# If you're on Linux, you need to run this script as a user with serial port access permission.

from tkinter import BOTH, END, LEFT 
from Crypto.Cipher import AES 
from tkinter.scrolledtext import ScrolledText
import tkinter as tk
import tkinter.ttk as ttk
import serial
import serial.tools.list_ports
import threading
import time
import requests
import os
import json

class PysweeperApp:
    def __init__(self, master=None):
        # build ui
        self.toplevel4 = tk.Tk() if master is None else tk.Toplevel(master)
        self.frame10 = ttk.Frame(self.toplevel4)
        self.labelframe1 = ttk.Labelframe(self.frame10)
        self.radiobutton9 = ttk.Radiobutton(self.labelframe1)
        self.rb = tk.IntVar(value=0)
        self.radiobutton9.configure(text='Service Mode', value='0', variable=self.rb)
        self.radiobutton9.pack(anchor='w', side='top')
        self.radiobutton10 = ttk.Radiobutton(self.labelframe1)
        self.radiobutton10.configure(text='Autoboot', value='1', variable=self.rb)
        self.radiobutton10.pack(anchor='w', side='top')
        self.radiobutton11 = ttk.Radiobutton(self.labelframe1)
        self.radiobutton11.configure(text='Normal Boot', value='2', variable=self.rb)
        self.radiobutton11.pack(anchor='w', side='top')
        self.radiobutton12 = ttk.Radiobutton(self.labelframe1)
        self.radiobutton12.configure(text='Custom S/N', value='3', variable=self.rb)
        self.radiobutton12.pack(anchor='w', side='top')
        self.entry1 = ttk.Entry(self.labelframe1)
        self.entry1.configure(width='8')
        self.entry1.pack(side='top')
        self.labelframe1.configure(height='200', text='Emulator Mode', width='200')
        self.labelframe1.pack(anchor='n', fill='both', side='top')
        self.frame1 = tk.Frame(self.frame10)
        self.frame2 = tk.Frame(self.frame1)
        self.label1 = tk.Label(self.frame2)
        self.label1.configure(compound='top', text='Port:')
        self.label1.pack(pady='4', side='left')
        self.combobox2 = ttk.Combobox(self.frame2)
        self.cbsel = tk.StringVar(value='')
        self.combobox2.configure(textvariable=self.cbsel, width='7')
        self.combobox2.pack(side='right')
        self.combobox2.configure(postcommand=updatecom)
        self.frame2.configure(height='200', width='200')
        self.frame2.pack(side='top')
        self.button1 = ttk.Button(self.frame1)
        self.button1.configure(text='Start Service')
        self.button1.pack(fill='x', side='top')
        self.button1.configure(command=startsv)
        self.button2 = ttk.Button(self.frame1)
        self.button2.configure(text='Stop Service')
        self.button2.pack(fill='x', side='top')
        self.button2.configure(command=stopsv)
        self.button3 = ttk.Button(self.frame1)
        self.button3.configure(text='Guide')
        self.button3.pack(fill='x', side='top')
        self.button3.configure(command=guide)
        self.button4 = ttk.Button(self.frame1)
        self.button4.configure(text='About')
        self.button4.pack(fill='x', side='top')
        self.button4.configure(command=about)
        self.frame1.configure(height='200', width='200')
        self.frame1.pack(fill='both', side='top')
        self.frame10.configure(height='200', width='200')
        self.frame10.pack(side='left')
        self.frame12 = ttk.Frame(self.toplevel4)
        self.labelframe2 = ttk.Labelframe(self.frame12)
        self.text1 = ScrolledText(self.labelframe2)
        _text_ = '''pysweeper, upload date: 16/8/21\nPlease select a COM port and press [Start Service].\n'''
        self.text1.insert('0.0', _text_)  
        self.text1.configure(blockcursor='false', height='10', insertunfocussed='hollow', relief='flat')
       	self.text1.configure(state='disabled', width='52')
        self.text1.pack(expand='true', fill='both', side='top')
        self.checkbutton1 = ttk.Checkbutton(self.labelframe2)
        self.rdbg = tk.BooleanVar(value='False')
        self.checkbutton1.configure(offvalue='False', onvalue='True', text='Response Debug', variable=self.rdbg)
        self.checkbutton1.pack(side='left')
        self.checkbutton2 = ttk.Checkbutton(self.labelframe2)
        self.keyWarn = tk.BooleanVar(value='True')
        self.checkbutton2.configure(offvalue='False', onvalue='True', text='Missing Keys Alert', variable=self.keyWarn)
        self.checkbutton2.pack(padx='8', side='left')
        self.button5 = ttk.Button(self.labelframe2)
        self.button5.configure(text='Clear Monitor')
        self.button5.pack(anchor='e', expand='true', padx='0', side='right')
        self.button5.configure(command=clearmon)
        self.labelframe2.configure(height='200', text='Protocol Monitor', width='200')
        self.labelframe2.pack(expand='true', fill='both', side='top')
        self.frame12.configure(height='200', width='200')
        self.frame12.pack(ipady='27', side='top')
        self.toplevel4.configure(borderwidth='2', height='200', width='200')

        # Main widget
        self.mainwindow = self.toplevel4
 

    def run(self):
        self.mainwindow.mainloop()


ser = serial.Serial()
running = False;
storedsl = ''
       
def msg(ms): 
    app.text1['state'] = 'normal'
    app.text1.insert(END, ms+'\n')
    app.text1['state'] = 'disabled'
    app.text1.see(tk.END)

def clearmon():
    app.text1['state'] = 'normal'
    app.text1.delete("1.0",tk.END)
    app.text1['state'] = 'disabled' 

def guide():
    clearmon()
    msg("Please refer to PSPx/psx-place threads to restore your PSP™.")
    msg("\nhttps://www.pspx.ru/forum/showthread.php?p=1229948 (Russian, frequently updated)")
    msg("\nhttps://www.psx-place.com/threads/baryon-sweeper-r1-release-unbrick-1000-2000-and-3000-psp-consoles.32503/ \n(English, less frequent updates)")

def about():
    clearmon()
    msg("BaryonSweeper - a JigKick internal service tool emulator")
    msg("Brought to you by patience and perserverance of:\n")
    msg("M4j0r - Syscon Voltage Fault Injection glitch help\n")
    msg("Wildcard - Syscon glitching and dumping\n")
    msg("Proxima - Firmware reverse engineering, battery authentication response generator script\n")
    msg("khubik - Emulator code, GUI design, authentication script porting\n")
    msg("dogecore - Authentication script porting, GUI code, emulator threading fix\n")
    msg("Mathieu Hervais - decrypt-sp & decrypt-OS2 homebrew code\n")
    msg("SSL/Zerotolerance - re-encryption for Math's homebrews\n")
    msg("zecoxao - decrypt-sp & decrypt-os2 PC ports, boards supply, authentication script porting help\n")
    msg("Yoti - decrypt-sp improvements, MSID Dumper, contribution to PSPx.ru's 3000 series JigKick hacking thread, PSP 3000 supplier (<3), PSP 3000 unbrick PoC\n")
    msg("ErikPshat - Useful intel about JigKick, PSPx.ru's 3000 series JigKick hacking thread contribution, creation of functional JigKick memcard clone from original dump, userguides for MSID dumping and JigKick memory card creation\n")
    msg("Boryan, lport3, dx3d and many others from PSPx.ru's 3000 JigKick hacking thread - battery communication dumps and protocol reversal, one wire UART adapter schematics and more!\n")
    msg("lolivera - PSP 3000 unbrick PoC, TA-095 testing\n")
    msg("Sean Shablack aka Kyp40 aka FBIsoBOT - Syscon glitching and dumping, simplest one wire UART adapter schematic ever\n")
    msg("预见 (zakezzzz) - TA-092 testing\n")
    msg("dee008 - Portable PSP battery controller emulator, PSP Street K-line pin location\n")
    msg("[!] Please do note that this tool is free and open-source. If you paid for it, demand a refund in full.\n")
    app.text1.see(1.0)

def startsv():
    global running
    global storedsl
    if running == True: return

        
    serialn = bytearray(4)
    op = app.rb.get()
    portsel = app.cbsel.get()
    if not portsel:
        msg("No port selected.")
        return 
    if (op == 9):
        msg("No option selected.")
    else:
        hexstr = ""
        if (op == 0):
            hexstr = "FFFFFFFF"
        if (op == 1):
            hexstr = "00000000"
        if (op == 2):
            hexstr = "34127856"
        if (op == 3):
            hexstr = app.entry1.get().upper()
        if (len(hexstr) != 8):
            msg("S/N must be 8 characters long.")
            return 
        try:
            serialn = bytearray.fromhex(hexstr)
        except ValueError:
            msg("Invalid S/N. Use only hex digits (0-9, A-F). ")
            return

        serialn[0::2], serialn[1::2] = serialn[1::2], serialn[0::2]
        running = True
        # spastic code
        if os.path.exists('/dev/serial/by-id'):
            for sl in os.listdir('/dev/serial/by-id'):
                if os.path.basename(os.readlink('/dev/serial/by-id/' + sl)) == os.path.basename(portsel):
                    storedsl = '/dev/serial/by-id/' + sl
                    # msg(storedsl)
        else: storedsl = ''
        t = threading.Thread(target=emuloop, args=(portsel, serialn))
        t.start()

def stopsv():
    global running
    running = False
    ser.close()

def updatecom():
    app.combobox2['values'] = ''
    for port in serial.tools.list_ports.comports():
        app.combobox2['values'] += port.device

def openport(pname):
    try:
        global ser
        ser = serial.Serial(port=pname, baudrate=19200, bytesize=8, parity=serial.PARITY_EVEN, stopbits=serial.STOPBITS_TWO)
        ser.reset_input_buffer()
        ser.reset_output_buffer()
        return 0
    except serial.SerialException:
        msg("Port " + pname + " is busy, not present or you don't have permissions to use it.")
        return 1
    except Exception as e:
        msg("An exception occurred during port opening: " + repr(e))
        return 1

def readpacket(key):
    mesg = bytearray()
    hello = ser.read(1) # 1
    if hello.hex() == key:
        len = ser.read(1) # 2
        opcode = ser.read(1) # 3
        if len.hex() != "02":
            msglen = (int.from_bytes(len, byteorder='little', signed=False) - 2)
            while (ser.in_waiting < (msglen + 1)):
                time.sleep(0.001)
            mesg = bytearray(msglen)
            mesg = ser.read(msglen)
            csum = ser.read(1)
            msg(hello.hex().upper() + ' ' + len.hex().upper() + ' ' + opcode.hex().upper() + ' ' + mesg.hex().upper() + ' ' + csum.hex().upper())
        else:
            csum = ser.read(1)
            msg(hello.hex().upper() + ' ' + len.hex().upper() + ' ' + opcode.hex().upper() + ' ' + csum.hex().upper())
        if key == "5a": return (hello, len, opcode, mesg, csum, True)
        else: return (0, 0, 0, 0, 0, False)
    else: return (0, 0, 0, 0, 0, False)

def writewithchecksum(header, mesg):
    ser.write(bytes.fromhex(header))
    ser.write(mesg)
    ser.write(checksum(header + mesg.hex()))

def emuloop(pname, sn):
    if openport(pname) == 1: return
    challenge1b = bytearray()
    msg("Service started.")
    msg("Using serial " + sn.hex().upper())
    try:
        while ser.is_open and running:
            time.sleep(0.001)
            if ser.in_waiting >= 4:
                packet = readpacket("5a")
                if packet[5] == True:
                    if packet[0].hex() == "5a":
                        if packet[2].hex() == "01":
                            ser.write(bytes.fromhex("a5050610c30676"))
                        elif packet[2].hex() == "0c":
                            writewithchecksum("a50606", sn)
                        elif packet[2].hex() == "80":
                            screq = packet[3]
                            version = str(screq[0])
                            if version not in keystore:
                                response1 = bytes.fromhex("ffffffffffffffff")
                                if app.keyWarn.get():
                                    msg(
                                    "==================================================\n" + 
                                    "WARN: Key " + hex(version)[-2:].upper() +
                                    " not found, is your PSP unsupported?\n" +
                                    "Answering with placeholders.\n" +
                                    "==================================================")
                            else:
                                req = screq[1:]
                                data=MixChallenge1(version,req)
                                challenge1a=AES.new(bytes(keystore[version]), AES.MODE_ECB).encrypt(bytes(MatrixSwap(data)))
                                second = bytearray(0x10)
                                second[:] = challenge1a[:]
                                challenge1b=MatrixSwap(AES.new(bytes(keystore[version]), AES.MODE_ECB).encrypt(bytes((second))))
                                response1 = bytes(challenge1a[0:8]) + bytes(challenge1b[0:8])
                            writewithchecksum("a51206", response1)
                        elif packet[2].hex() == "81":
                            data2=MixChallenge2(version,challenge1b[0:8])
                            challenge2=AES.new(bytes(keystore[version]), AES.MODE_ECB).encrypt(bytes(MatrixSwap(data2)))
                            response2=(AES.new(bytes(keystore[version]), AES.MODE_ECB).encrypt(challenge2))
                            writewithchecksum("a51206", response2)
                        elif packet[2].hex() == "03":
                            ser.write(bytes.fromhex("a5040636100a"))
                        elif packet[2].hex() == "07":
                            ser.write(bytes.fromhex("a50406080741"))
                        elif packet[2].hex() == "0b":
                            ser.write(bytes.fromhex("a504060f0041"))
                        elif packet[2].hex() == "09":
                            ser.write(bytes.fromhex("a5040601044b"))
                        elif packet[2].hex() == "02":
                            ser.write(bytes.fromhex("a503061b36"))
                        elif packet[2].hex() == "04":
                            ser.write(bytes.fromhex("a504066810d8"))
                        elif packet[2].hex() == "16":
                            ser.write(bytes.fromhex("a51306536f6e79456e65726779446576696365736b"))
                        elif packet[2].hex() == "0d":
                            ser.write(bytes.fromhex("a507069d1010281454"))
                        elif packet[2].hex() == "08":
                            ser.write(bytes.fromhex("a50406e2046a"))
             
                    readpacket("a5")

    except serial.SerialException:
        if running:
            msg("Port disconnected. Retrying in 1 second.")
            time.sleep(1)
            updatecom()
            if pname in app.combobox2['values']:
                emuloop(pname, sn)
            else:
                msg("Port didn't come back online. ")
                msg("Service stopped, COM port closed.")
                ser.close() 
                return
        else:
            msg("Service stopped, COM port closed.")
            return
    
    except OSError:
        if running:
            msg("Port disconnected. Retrying in 2 seconds.")
            time.sleep(2)
            updatecom()
            newname = '/dev/' + os.path.basename(os.readlink(storedsl))
            if newname in app.combobox2['values']:
                emuloop(newname, sn)
            else:
                msg("Port didn't come back online. ")
                msg("Service stopped, COM port closed.")
                ser.close() 
                return

    except Exception as e:
        msg("An exception occurred in IO loop: " + repr(e))
        ser.close()
        return

def checksum(packet):
    bp = bytearray.fromhex(packet)
    Sum = sum(bp)
    sh = hex(Sum)
    temp = bytes.fromhex(sh[len(sh)-2:len(sh)])
    return (255 - int.from_bytes(temp, byteorder='little', signed=False)).to_bytes(1, byteorder="little", signed=False)

#PSP v4 Syscon Handshake Calculator by Proxima (R)
def MixChallenge1(version, challenge):
    data = [ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0]
    secret1=challenge1_secret[version]
    data[0] =secret1[0]
    data[4] =secret1[1]
    data[8] =secret1[2]
    data[0xC] =secret1[3]
    data[1] =secret1[4]
    data[5] =secret1[5]
    data[9] =secret1[6]
    data[0xD] =secret1[7]
    data[2] = challenge[0]
    data[6] = challenge[1]
    data[0xA] = challenge[2]
    data[0xE] = challenge[3]
    data[3] = challenge[4]
    data[7] = challenge[5]
    data[0xB] = challenge[6]
    data[0xF] = challenge[7]
    return data


def MixChallenge2(version, challenge):
    data = [ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0]
    secret2=challenge2_secret[version]
    data[0] =challenge[0]
    data[4] =challenge[1]
    data[8] =challenge[2]
    data[0xC] =challenge[3]
    data[1] =challenge[4]
    data[5] =challenge[5]
    data[9] =challenge[6]
    data[0xD] =challenge[7]
    data[2] = secret2[0]
    data[6] = secret2[1]
    data[0xA] = secret2[2]
    data[0xE] = secret2[3]
    data[3] = secret2[4]
    data[7] = secret2[5]
    data[0xB] = secret2[6]
    data[0xF] = secret2[7]
    return data

newmap = [
    0x00, 0x04, 0x08, 0x0C, 0x01, 0x05, 0x09, 0x0D, 0x02, 0x06, 0x0A, 0x0E, 0x03, 0x07, 0x0B, 0x0F, 
]

def MatrixSwap(key):
    temp = [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0]
    for i in range(0,len(key)):
        temp[i] = key[newmap[i]]
    return temp[0:len(key)]

def loadkeys():
    keysfile = open("keys.json")
    keys = json.load(keysfile)
    global kv
    kv = keys['keyversion']
    global keystore
    global challenge1_secret
    global challenge2_secret
    keystore = keys['keystore']
    challenge1_secret = keys['challenge1_secret']
    challenge2_secret = keys['challenge2_secret']
    keysfile.close()

    msg("Key version: " + str(kv))
    
def updatekeys():
    loadkeys()
    url = 'https://raw.githubusercontent.com/khubik2/pysweeper/master/keys.json'
    try:
        r = requests.get(url, allow_redirects=True)
        open('temp.json', 'wb').write(r.content)
        downfile = open("temp.json")
        ckeys = json.load(downfile)
        downfile.close()
        if ckeys['keyversion'] > kv:

            os.remove("keys.json")
            os.rename('temp.json', 'keys.json') 
            msg("Keys have been updated.")
            loadkeys()
        else: 
            msg("No key updates available.")
            os.remove('temp.json')

    except Exception:
        msg("Can't update keys - no connection to Internet.")
        return

    if os.path.exists('temp.json'): os.remove('temp.json')

if __name__ == '__main__':
    app = PysweeperApp()
    updatekeys()
    app.run()


