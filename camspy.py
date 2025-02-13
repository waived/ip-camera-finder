import threading
import random
import time
import os
import sys
import requests
import socket
from scapy.all import *

active = 0

#setup colors
r = '\033[1m\033[31m' #red
w = '\033[1m\033[37m' #white
g = '\033[1m\033[32m' #green
c = '\033[1m\033[36m' #cyan

def syn_probe(ip, port):
    global active

    active +=1 
  
    try:
        #send tcp-syn request to endpoint
        response = sr1(IP(dst=ip)/TCP(dport=int(port), flags="S"), timeout=5, verbose=0)

        if response and response.haslayer(TCP):
            #if syn-ack response / port open
            if response[TCP].flags == 0x12:
                
                #use http-detect for front-end camera interfaces
                if int(port) == 80 or int(port) == 443 or int(port) == 8443:
                    http_detect(ip, port)
                #check for valid rstp feed
                elif int(port) == 554:
                    rtsp_detect(ip)
                #check for valid rtmp feed
                elif int(port) == 1935:
                    rtmp_detect(ip)
    except:
        pass

    active -=1

def http_detect(ip, port):
    strings = [
        'mjpeg', 'amcrest', 'reolink', 'honeywell', 'api.arlo.com',
        'h264', 'foscam', 'ws://', 'kasa cam', 'circle.js', 'webrtc.js',
        'video.cgi', 'dahua', 'axis 207', 'ubiquiti', 'arlo.js', 'rtsp',
        '<video src="', 'JWPlayer', 'vivotek', 'eufy', 'cloud.logi.com',
        'webcam', 'web_cam', 'camera', 'vivint', 'player.js', 'cloud.arlo.com',
        'hikvision', 'panasonic', 'zmodo', 'lorex', 'hi3510', 'unifi.js',
        'axiscam.js' 'axis-cgi', 'stream.cgi', 'param.js', 'unifiPlayer.js',
        'mjpg/video.cgi', '/ISAPI', 'cameraControl.js', 'boschPlayer.js',
        'motionDetection.js', 'hdPlayer.js'
    ]
    try:
        url = f'http://{ip}:{port}'
  
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            #set html content
            content = response.text.lower()

            #set html headers
            headers = response.headers
      
            #header check
            for item1 in strings:
                if item1.lower() in headers:
                    print(f'     {g}Possible camera feed detected @ http://{w}{ip}{g}:{w}{port}')
                    break
      
            #html content check
            for item2 in strings:
                if item2.lower() in content:
                    print(f'     {g}Possible camera feed detected @ http://{w}{ip}{g}:{w}{port}')
                    break
                    
            print(f'     {w}Front-end detected {ip}:{port} but no camera signature found...')
    except:
        pass

def rtmp_detect(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, 1935))

        #build 1536-byte RTMPv3 handshake
        rtmp_handshake = b'\x03' + b'\x00' * 1535
    
        s.sendall(rtmp_handshake)

        response = s.recv(1536)

        if response.startswith(b'\x03\x00'):
            print(f'     {g}Possible camera feed detected @ rtmp://{w}{ip}{g}:{w}1935')

        s.close()  
    except:
      pass
    
def rtsp_detect(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, 554))

        rtsp_req = f'DESCRIBE rtsp://{ip} RTSP/1.0\r\nCSeq: 1\r\n\r\n'
        s.sendall(rtsp_req.encode('utf-8'))

        response = s.recv(1024)
    
        #print('---> RTSP Response: ' + response.decode('utf-8', errors='ignore'))

        if '200 OK' in response.decode('utf-8', errors='ignore'):
            print(f'     {g}Possible camera feed detected @ rtsp://{w}{ip}{g}:{w}554')
      
        s.close()
    except:
      pass
  
def make_ip():
    while True:
        ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        
        octets = ip.split('.')
        first_octet = int(octets[0])
        second_octet = int(octets[1])

        if first_octet == 10:
            continue  # Class A private range (10.x.x.x)
        if first_octet == 172 and 16 <= second_octet <= 31:
            continue  # Class B private range (172.16.x.x to 172.31.x.x)
        if first_octet == 192 and second_octet == 168:
            continue  # Class C private range (192.168.x.x)
        if first_octet == 169 and second_octet == 254:
            continue  # Link-local range (169.254.x.x)
        
        return ip

def main():
    global active 
  
    os.system('clear')

    if os.geteuid() != 0:
        sys.exit('\r\nScript requires elevation!\r\n')
  
    print(f'''{r}
         _________                __________
        /        /               /         /
       /   _____/_______________ \     ___/__________ ___
      /   /____/  __  /        /__\     \/   __  /  //  /
     /        /      /  /  /  /         /  _____/__    /
    /________/__//__/__/__/__/_________/__/    /______/''')
    
    input(f'\r\n{g}Ready? Strike <ENTER> to scan and <CTRL+C> to quit...\r\n')

    ports = [80, 443, 554, 1935, 8443, 37777]

    while True:
        try:
            #generate random endpoint
            ip = make_ip()
            print(f'\r\n{w}Scanning new host: {ip}')
      
            for port in ports:
                print(f'{w}---> Probing {c}{port}')
                x = threading.Thread(target=syn_probe, args=(ip, port))
                x.daemon = True
                x.start()

            time.sleep(1)
    
            while active > 0:
                #wait for probes to finish
                pass
      
        except KeyboardInterrupt:
            sys.exit()
        except Exception as e:
            print(f'\r\n{e}\r\n')

if __name__ == '__main__':
  main()
