import threading
import time
from socket import *
from thread import *
import socket
import sys
import zlib,sys,base64
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
ipList=[]
host = '192.168.43.170'
#host = '192.168.43.227'
#host='127.0.0.1'
ind=0
fData=""
users=["akshat","dell","govind"]
autUsers=[]
password=[b'aaaaaaaaaaaaaaaaaaaaaaaa',b'bbbbbbbbbbbbbbbbbbbbbbbb',b'bbbbbbbbbbbbbbbbbcbbbccc']
key=b'ABCDEFGHIJKLMNOPQRSTWXYZ'
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]
x=2
connectPort = 50000+x
sockC = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sockC.bind((host, connectPort))
sockC.listen(5)

receivePort=40000+x
sockR=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sockR.bind((host,receivePort))
sockR.listen(5)

sendPort=30000+x
sockS=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sockS.bind((host,sendPort))
sockS.listen(5)

autPort=20000+x
autSock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
autSock.bind((host,autPort))
autSock.listen(5)

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


def sendList():
    for all in ipList:
        all[0].send(str(len(ipList)))
    print("Connected Clients : "+str(len(ipList))+"\n")
    time.sleep(0.1)
    for all in ipList:
        i=0
        for i in range(len(ipList)):
            all[0].send(ipList[i][1])
    
def clientthread(conn):
    print("connected to "+str(conn))
    addr=conn.recv(2048)
    name=conn.recv(2048)
    temp=[conn , str(name)]
    ipList.append(temp)
    print(ipList)
    


class connectClient(threading.Thread):
    def __init__(self,):
        threading.Thread.__init__(self)

                
    def run(self):
        
        while True:
            send=threading.Timer(3,sendList)
            send.start()
            conn,addr=sockC.accept()
            start_new_thread(clientthread,(conn,))
            
def authenticate_user(autCon):
    enc=autCon.recv(1024)
    print(enc)
    i=0
    flag=1
    for i in range(len(password)):
        decry=decrypt(enc,password[i])
        print(decry)
        decry=str(decry)
        '''if ((ord(decry[i])>=65 and ord(decry[i])<=90) or (ord(decry[i])>=97 and ord(decry[i])<=122)):
            flag=1
        else:
            flag=0'''
        if len(decry)==0:
            flag=0
        else:
            flag=1
            break
    autCon.send(str(flag))
        
    

    
class authenticateUser(threading.Thread):
    def __init__(self,):
        threading.Thread.__init__(self)
    def run(self):
        while True:
            autCon,autAddr=autSock.accept()
            start_new_thread(authenticate_user,(autCon,))

def receiveData(connR):
    connR.send("Enter the name of the user")
    index=connR.recv(1024)
    global ind
    ind=int(index)
    print("to be sent to "+str(ind))
    while True:
        data=connR.recv(1024)
        if data=="complete":
            break
        global fData
        fData=fData+data
    with open('abc.txt','wb')as fob:
        fob.write(fData)

    
    print("done writing")
    

    
class receiveFromClient(threading.Thread):
    def __init__(self,):
        threading.Thread.__init__(self)

    def run(self):
        while True:
            connR,addrR=sockR.accept()
            start_new_thread(receiveData,(connR,))

def sendData(connS):
    print("in sendData function\n"+str(connS))
    cName=connS.recv(1024)
    
    for all in ipList:
        if (all[1]==cName):
            print("comparison success")
            for i in range(len(users)):
                if users[i]==cName:
                    break
            
            with open('abc.txt', 'rb') as file_to_send:
                for data in file_to_send:
                    data1=encrypt(data,password[i])
                    connS.sendall(data1)
            #connS.send(fData)
            print("data is "+str(fData))
            time.sleep(0.1)
            connS.send(encrypt("complete",password[i]))
            print("send done")
        

            
    
    

class sendToClient(threading.Thread):
    def __init__(self,):
        threading.Thread.__init__(self)

    def run(self):
        while True:
            connS,addrS=sockS.accept()
            start_new_thread(sendData,(connS,))
        
        




def Main():
        allConnect=connectClient()
        allConnect.start()
        time.sleep(3)
        authen=authenticateUser()
        authen.start()
        receiveData=receiveFromClient()
        receiveData.start()
        time.sleep(1)
        sendData=sendToClient()
        sendData.start()
        sendData.join()
        receiveData.join()
        authen.join()
        allConnect.join()
        

if __name__=='__main__':
    Main()
