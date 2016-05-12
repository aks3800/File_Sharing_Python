from socket import*
import socket
import time
import threading
import zlib,sys,base64
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES


import sys
if not sys.hexversion > 0x03000000:
    version = 2
else:
    version = 3
if len(sys.argv) > 1 and sys.argv[1] == "-cli":
    print("Welcome to the DoSSier program!")
    
    isCLI = True
else:
    isCLI = False


if version == 2:
       from Tkinter import *
       from tkFileDialog import asksaveasfilename
       from tkFileDialog import askopenfilename
       from tkMessageBox import showerror
if version == 3:
       from tkinter import *
       from tkinter.filedialog import asksaveasfilename

import random
import math
'''#import sys, os
#if not sys.hexversion > 0x03000000:
 #   version = 2
else:
    version = 3

if version == 2:'''
'''from Tkinter import *
from tkFileDialog import asksaveasfilename
from tkFileDialog import askopenfilename
from tkMessageBox import showerror'''
'''if version == 3:
	from tkinter import *
	from tkinter.filedialog import asksaveasfilename
	from tkinter.fileDialog import askopenfilename
	from tkinter.messagebox import showerror

'''
global statusConnect
x=11
fData=""
#sendFileName=''
sendFileName='myTransfer.txt'
recvFileName='myRecFile.txt'
connectedUserList=[]
host='192.168.200.50'
#host = '192.168.43.170'
#host = '192.168.43.227'
#host='127.0.0.1'
cliIp = socket.gethostbyname(socket.gethostname())
cliName=socket.gethostname()
connectPort = 50000+x
sockC = socket.socket()
sendPort=40000+x
sockS=socket.socket()
receivePort=30000+x
sockR=socket.socket()
autPort=20000+x
autSock=socket.socket()

def updateListFun():
       conNum=sockC.recv(1024)
       list=[]
       print("No. of connected users are :"+conNum+"\n")
       i=0
       for i in range(int(conNum)):
           recName=sockC.recv(1024)
           list.append(recName)
       global connectedUserList
       connectedUserList=list
       print(connectedUserList)
       writeToActive(connectedUserList)
       
updateList=threading.Timer(0.1,updateListFun)        


root = Tk()
#root.tk.call('wm', 'iconbitmap', root._w, '-default', 'dossieri.ico')
import os, random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]

'''def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)'''

#key=b'ABCDEFGHIJKLMNOPQRSTWXYZ'
#key = b'\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18'
key=b'bbbbbbbbbbbbbbbbbbbbbbbb'
def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(message))

def decrypt(ciphertext, key):
       ciphertext=base64.b64decode(ciphertext)
       iv=ciphertext[:16]
       cipher = AES.new(key, AES.MODE_CBC, iv)
       return unpad(cipher.decrypt(ciphertext[16:] ))

'''
def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")'''

def encrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
        
    enc = encrypt(plaintext, key)
    with open("(E)ncryptedfile.txt", 'wb') as fo:
        fo.write(enc)
        print("encrypted", enc)
        writeToScreen("Successfully Encrypted!!")

def decrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    with open("(D)ecryptedfile.txt", 'wb') as fo:
        fo.write(dec)
        print("decrypted", dec)
        writeToScreen("Successfully Decrypted!!")

'''
def encrypt(key,fileName):
    chunkSize=64*1024
    outputFile="(E)ncrypted"+fileName
    fileSize=str(os.path.getsize(fileName)).zfill(16)
    IV=''

    for i in range(16):
           IV+=chr(random.randint(0,0xFF))


    encryptor=AES.new(key,AES.MODE_CBC,IV)

    with open(fileName,'rb')as inFile:
        with open(outputFile,'wb')as outFile:
            outFile.write(fileSize.encode('utf-8'))
            outFile.write(IV)

            while True:
                chunk=inFile.read(chunkSize)

                if len(chunk)==0:
                    break
                elif len(chunk)%16!=0:
                    chunk += ' ' * (16 - (len(chunk) % 16))
                outFile.write(encryptor.encrypt(chunk))
'''
'''
def decrypt(key,fileName):
    chunkSize=64*1024
    outputFile=fileName[11:]
    #outputFile="(D)"+outputFile
    with open(fileName,'rb')as inFile:
        fileSize=long(inFile.read(16))
        IV=inFile.read(16)

        decryptor=AES.new(key,AES.MODE_CBC,IV)

        with open(outputFile, 'wb')as outFile:
            while True:
                chunk=inFile.read(chunkSize)

                if len(chunk)==0:
                    break
                outFile.write(decryptor.decrypt(chunk))
            outFile.truncate(fileSize)

'''
def getKey(password):
    hasher=SHA256.new(password.encode('utf-8'))
    return hasher.digest()

'''
def main_encrypt():
       password=raw_input("Password :")
       encrypt_file('compressed.txt', getKey(password))
       print("Done Encryption")
       writeToScreen("Done")

def main_decrypt():
       password=raw_input("Password :")
       decrypt_file(recvFileName,getKey(password))
       print("Done Decryption")
       writeToScreen("Done")
'''
def main_encrypt():
       
       encrypt_file('compressed.txt', key)
       print("Done Encryption")
       writeToScreen("Done")
       #send1()
       textdata = (text_input.get("1.0",'end-1c'))
       writeToScreen("Now You Can send The file .. ")
       writeToScreen("for the same, write the name of receiver & then press send")

       if textdata != " ":
           send.config(state=NORMAL)
        
def main_decrypt():
       decrypt_file(recvFileName,key)
       print("Done Decryption")
       writeToScreen("Done")


def compression():
       text=open(sendFileName,'r').read()
       print("size of file : "+str(sys.getsizeof(text)))
       writeToScreen("size of file : "+str(sys.getsizeof(text)))
       compressed=base64.b64encode(zlib.compress(text,9))
       print("size of compressed file : "+str(sys.getsizeof(compressed)))
       writeToScreen("size of compressed file : "+str(sys.getsizeof(compressed)))
       open('compressed.txt','w').write(compressed)

def decompression():
       readFile=open("(D)ecryptedfile.txt",'r').read()
       decompressed=zlib.decompress(base64.b64decode(readFile))
       print("size of decompressed file : "+str(sys.getsizeof(decompressed)))
       writeToScreen("size of decompressed file : "+str(sys.getsizeof(decompressed)))
       open('FinalDecompressed.txt','w').write(decompressed)
                                    
       
             
       
def donothing():
   filewin = Toplevel(root)
   button1 = Button(filewin, text="Do nothing button")
   button1.pack() 



def userinput(text):
    writeToScreen(text)
    #processUserText(event)
    textdata = (text_input.get("1.0",'end-1c'))
    #if textdata[END] == "\n":
    #writeToScreen(textdata)
                     
    print (textdata)
    #writeToScreen(textdata)
    
    ans2=textdata
    writeToScreen(ans2)
    text_input.delete(1.0, END)
                  
    
    
    

def writeToActive(text):
       ip_body_text.config(state=NORMAL)
       ip_body_text.insert(END, '\n')
       ip_body_text.insert(END, text)
       ip_body_text.yview(END)
       ip_body_text.config(state=DISABLED)
       
def writeToScreen(text):
       main_body_text.config(state=NORMAL)
       main_body_text.insert(END, '\n')
       main_body_text.insert(END, text)
       main_body_text.yview(END)
       main_body_text.config(state=DISABLED)

def send1():
           writeToScreen("Now You Can send The file .. ")
           writeToScreen("for the same, you can write the name of receiver and then press send")
           #status=Label(self,text="Sending File...", bd=1, relief=SUNKEN, anchor=W)
           ques1=sockS.recv(1024)
           #ans1=raw_input(ques1)
           global ans2
           ans2=userinput(ques1)
           print(ans2)
           writeToScreen(ans2)       
   
def processUserText(event):
       """Takes text from text bar input and calls processUserCommands if it begins with '/'. """
       #textdata = text_input.get()
       textdata = (text_input.get("1.0",'end-1c'))
       if textdata[0] != " ":
              writeToScreen(textdata)
                     
       print (textdata)
       #writeToScreen(textdata)
       text_input.delete(1.0, END)

def authenticate_user():
       string=cliName
       encr=encrypt(string,key)
       print(encr)
       autSock.send(encr)
       flag=int(autSock.recv(1024))
       return flag
       
  

def toOne():
    global clientType
    flag=authenticate_user()
    if flag==1:
        print("you are good to go")
    else:
        print("authentication failure")
        MyFrame().destroy
        sockC.close()
        
    print("in toOne func: Set to SENDER")
    writeToScreen("Set to SENDER!")
    clientType = 1
    browse.config(state=NORMAL)
    compressb.config(state=NORMAL)
    encryptb.config(state=NORMAL)
    send.config(state=DISABLED)
    receive.config(state=DISABLED)
    decryptb.config(state=DISABLED)
    decompressb.config(state=DISABLED)

	
def toTwo():
       global clientType
       clientType = 0
       print("in toTwo func: Set to RECEIVER")
       writeToScreen("Set to RECEIVER!")
       browse.config(state=DISABLED)
       compressb.config(state=DISABLED)
       encryptb.config(state=DISABLED)
       send.config(state=DISABLED)
       receive.config(state=NORMAL)
       decryptb.config(state=NORMAL)
       decompressb.config(state=NORMAL)
	

def contacts_add(listbox, root):
    """Add a contact."""
    aWindow = Toplevel(root)
    aWindow.title("Contact add")
    Label(aWindow, text="Username:").grid(row=0)
    name = Entry(aWindow)
    name.focus_set()
    name.grid(row=0, column=1)
    Label(aWindow, text="IP:").grid(row=1)
    ip = Entry(aWindow)
    ip.grid(row=1, column=1)
    Label(aWindow, text="Port:").grid(row=2)
    port = Entry(aWindow)
    port.grid(row=2, column=1)
    go = Button(aWindow, text="Add", command=donothing)
	#lambda:       contacts_add_helper(name.get(), ip.get(), port.get(), aWindow, listbox))
    go.grid(row=3, column=1)

#-----------------------------------------------------------------------------
# Contacts window

def contacts_window():
    """Displays the contacts window, allowing the user to select a recent
    connection to reuse.

    """
    global contact_array
    cWindow = Toplevel(root)
    cWindow.title("Contacts")
    cWindow.grab_set()
    scrollbar = Scrollbar(cWindow, orient=VERTICAL)
    listbox = Listbox(cWindow, yscrollcommand=scrollbar.set)
    scrollbar.config(command=listbox.yview)
    scrollbar.pack(side=RIGHT, fill=Y)
    buttons = Frame(cWindow)
    cBut = Button(buttons, text="Connect",command=donothing)
    cBut.pack(side=LEFT)
    dBut = Button(buttons, text="Remove",command=donothing)
    dBut.pack(side=LEFT)
    aBut = Button(buttons, text="Add",command=contacts_add(listbox, cWindow))
    aBut.pack(side=LEFT)
    buttons.pack(side=BOTTOM)
    listbox.pack(side=LEFT, fill=BOTH, expand=1)
'''

    for person in contact_array:
        listbox.insert(END, contact_array[person][1] + " " +
                       person + " " + contact_array[person][0])
'''   
 



class MyFrame(Frame):

       def __init__(self):
              Frame.__init__(self)
              self.master.title("DoSSier")

              self.master.rowconfigure(5, weight=1)
              self.master.columnconfigure(5, weight=1)
              self.grid(sticky=W+E+N+S)

              menubar = Menu(self.master)
              filemenu = Menu(menubar, tearoff=0)
              filemenu.add_command(label="New", command=donothing)
              filemenu.add_command(label="Open", command=donothing)
              filemenu.add_command(label="Save", command=donothing)

              filemenu.add_command(label="Save as...", command=donothing)
              filemenu.add_command(label="Close", command=donothing)

              filemenu.add_separator()
              filemenu.add_command(label="Exit", command=self.master.quit)
              menubar.add_cascade(label="File", menu=filemenu)
              editmenu = Menu(menubar, tearoff=0)
              editmenu.add_command(label="Undo", command=donothing)

              editmenu.add_separator()

              editmenu.add_command(label="Cut", command=donothing)
              editmenu.add_command(label="Copy", command=donothing)
              editmenu.add_command(label="Paste", command=donothing)
              editmenu.add_command(label="Delete", command=donothing)
              editmenu.add_command(label="Select All", command=donothing)

              menubar.add_cascade(label="Edit", menu=editmenu)

              menubar.add_command(label="Contacts", command=contacts_window)

              helpmenu = Menu(menubar, tearoff=0)
              helpmenu.add_command(label="Help Index", command=donothing)
              helpmenu.add_command(label="About...", command=donothing)
              menubar.add_cascade(label="Help", menu=helpmenu)

              self.master.config(menu=menubar)

              statusConnect = StringVar()
              statusConnect.set("Connect")
              #main_body3 = Frame(self)
              main_body1 = Frame(self, height=1, width=80)
              main_body = Frame(main_body1)

              main_bodyx = Frame(main_body)
              global main_body_text
              main_body_text = Text(main_bodyx, width=65, height=15.5)
              body_text_scroll = Scrollbar(main_bodyx)
              main_body_text.focus_set()
              body_text_scroll.pack(side=RIGHT, fill=Y)
              #main_body_text.bind("<Return>", processUserText)
              main_body_text.pack()
              #main_body_text.insert(END, "Welcome to the DoSSier program!")
              writeToScreen("Welcome to the DoSSier program!")
              body_text_scroll.config(command=main_body_text.yview)
              main_body_text.config(yscrollcommand=body_text_scroll.set)
              main_body_text.config(state=DISABLED)
              main_bodyx.pack()

              main_bodyy = Frame(main_body)
              global text_input
              text_input = Text(main_bodyy, width=65, height=7.5)
              text_scroll = Scrollbar(main_bodyy)
              text_scroll.pack(side=RIGHT, fill=Y)
              text_input.bind("<Return>", processUserText)
              body_text_scroll.config(command=text_input.yview)
              text_input.config(yscrollcommand=text_scroll.set)
              text_input.pack()
              main_bodyy.pack()
              
              
              option_buttons = Frame(self, height=20, width=40)

              
              
              global browse
              browse = Button(option_buttons, text="Browse", command=self.load_file, width=15)
              #browse.grid(column=1, sticky=W)
              browse.pack(side=LEFT)
              global compressb
              compressb = Button(option_buttons, text="Compress", command=compression, width=15)
              compressb.pack(side=LEFT)
              global encryptb
              encryptb = Button(option_buttons, text="Encrypt", command=main_encrypt, width=15)
              encryptb.pack(side=LEFT)
              global send
              send = Button(option_buttons, text="Send", command=self.send, width=15)
              send.pack(side=LEFT)
              global receive
              receive = Button(option_buttons, text="Receive", command=self.receive, width=15)
              receive.pack(side=LEFT)
              global decryptb
              decryptb = Button(option_buttons, text="Decrypt", command=main_decrypt, width=15)
              decryptb.pack(side=LEFT)
              global decompressb
              decompressb = Button(option_buttons, text="Decompress", command=decompression, width=15)
              decompressb.pack(side=LEFT)
              print("in frame init")
              
              connecter = Button(option_buttons, textvariable=statusConnect, command=self.connect(), width=10) #to set the clienttype connection
              #connecter.grid(column=0, sticky=W)
              #connecter.pack( side=LEFT)


              
              
              option_buttons.pack()
              main_body.pack( side=LEFT, fill=Y)

              main_bodyz = Frame(main_body1)
              global ip_body_text
              ip_body_text = Text(main_bodyz, width=29)
              scroll = Scrollbar(main_bodyz)
              scroll.pack(side=RIGHT, fill=Y)
              ip_body_text.bind("<Return>", processUserText)
              ip_body_text.pack(side=RIGHT,fill=Y)
              ip_body_text.insert(END, "Connected Users!")
              scroll.config(command=ip_body_text.yview)
              ip_body_text.config(yscrollcommand=scroll.set)
              ip_body_text.config(state=DISABLED)
              main_bodyz.pack()

              main_body1.pack(side=TOP)

              clientType = 1
              browse.config(state=DISABLED)
              compressb.config(state=DISABLED)
              encryptb.config(state=DISABLED)
              send.config(state=DISABLED)
              
              main_body2 = Frame(self)
              Radiobutton(main_body2, text="Sender", variable=clientType, value=1, command=toOne).pack(side=RIGHT,anchor=E, pady=2)
              Radiobutton(main_body2, text="Receiver", variable=clientType, value=0, command=toTwo).pack(side=RIGHT,anchor=E, pady=2)

              main_body2.pack(fill=X)

              global status
              status=Label(self,text="Preparing to do nothing...", bd=1, relief=SUNKEN, anchor=W)
              status.pack(side=BOTTOM, fill=X)




       
       def connect(self): #Connect to server
              print("in func connect")
              sockC.connect((host, connectPort))
              sockS.connect((host,sendPort))
              sockR.connect((host,receivePort))
              autSock.connect((host,autPort))
              updateList.start()
              print("Connected") #Connection successful
              writeToScreen("Succesfully Connected to Server!")
              #self.receive_msg()
              sockC.send(str(cliIp))
              time.sleep(0.5)
              sockC.send(str(cliName))



       
       def receive_msg(self):
              print("Preparing to receive")#Prepared to receive message
              writeToScreen("Preparing to receive")
              while True:
                     sockC.send(str(cliIp))
                     time.sleep(0.5)
                     sockC.send(str(cliName))
       
           

       def send(self):
              print("in send function")
              writeToScreen("Preparing to Send..")
              #status=Label(self,text="Sending File...", bd=1, relief=SUNKEN, anchor=W)
              ques1=sockS.recv(1024)
              #ans1=raw_input(ques1)
              global ans2
              ans2=userinput(ques1)
              #print(ans2)
              #writeToScreen(ans2)
            
              
              
              index=0
              while index<len(connectedUserList):
                     if connectedUserList[index]==ans2:
                            break
                     else:
                            index=index+1

              sockS.send(str(index))
              time.sleep(0.5)
              #fileN="(E)ncrypted"+sendFileName
              with open("(E)ncryptedfile.txt", 'rb') as file_to_send:
                     for data in file_to_send:
                            sockS.sendall(data)
              print("sending done")
              writeToScreen("Done Sending!!")
              time.sleep(0.1)
              sockS.send("complete")

       def receive(self):
              print("in receive fun")
              writeToScreen("Preparing to Receive..")
              fData=""
              sockR.send(cliName)
              time.sleep(0.1)
              while True:
                     data1=sockR.recv(1024)
                     data=decrypt(data1,key)
                     fData=fData+data
                     if data=="complete":
                            break
              with open(recvFileName,'wb')  as fob:
                     fob.write(fData)
              print("over")
              writeToScreen("Received Successfully!!")
      
       
       def load_file(self):
              fname = askopenfilename(filetypes=(("Text Files", "*.txt"),("mp3 files", "*.mp3"),("Template files", "*.tplate"),("HTML files", "*.html;*.htm"),("All files", "*.*") ))
              if fname:
                     try:
                            print("Browsed file :")
                            writeToScreen("Browsed File: ")
                            print(fname)
                            writeToScreen(fname)
                            with open(fname, 'rb') as fon:
                                   loadtext = fon.read()
                            with open(sendFileName, 'wb') as fown:
                                   fown.write(loadtext)
                            print("""here it comes: self.settings["template"].set(fname)""")
                     except:
                            showerror("Open Source File", "Failed to read file\n'%s'" % fname)
                            writeToScreen("Error opening file")
                     return


if __name__ == "__main__":
	
	#obj1=client()
	#obj1.run_client()		
	MyFrame().mainloop()
	sockC.close()
	
	
	
