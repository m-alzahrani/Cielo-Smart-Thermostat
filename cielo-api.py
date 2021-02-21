# THIS CODE ISN'T FINAL IT'S STILL NEED A LOT OF WORK
# I SHARED IT WITH YOU IF YOU CAN DEVELOPE HOME ASSISTANT HAVC PLUGIN OR YOU JUST FOR HAVING IDEA HOW DOES SMART CIELO API WORKS
#NOTE : I AM NOT A PROGRAMMER AND THIS IS MY FIRST PYTHON CODE EVER EXCEPT 'HELLO WORLD' PROJECT
#A LOT OF EDITING WILL BE DONE FOR THIS CODE SOME DATA ISN'T NECESSERY AND SOME ARE MISSING SO IF YOU HAVE ANY QUESTION OR SUGGESTION PLEASE DON'T HESITATE
#TWITTER : @MUH_ALZAHRANI
#SPECIAL THANKS FOR Nicholas Robinson HIS CODE HELPED ME A LOT TO GET ACCESS TO THE API
# https://github.com/nicholasrobinson/node-smartcielo

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import urllib
import websocket
from bs4 import BeautifulSoup
import _thread as thread
import json
import time
from base64 import b64decode
import calendar
from websocket import create_connection



#GET IP ADDRESS 123
ip_address = requests.get('https://api.ipify.org').text

User_name = #YOUR CIELO SMART USERNAME
Password =  #YOUR CIELO SMART PASSWORD

#EXAMPLE DATA COMMAND TO BE SEND TO TURN ON AC YOU CAN CHANGE DATA AS REQUIRED
json_data = '''{"H":"devicesactionhub","M":"broadcastActionAC","A":[{"tempRange":"","turbo":"off","mid":"daytrbgir5yi4p23wznsoifs","mode":"cool","modeValue":"","temp":"24","tempValue":"","power":"on","swing":"auto","fanspeed":"high","scheduleID":"","macAddress":"MAC ADDRESS HERE","applianceID":1880,"performedAction":"power","performedActionValue":"on","actualPower":"off","modeRule":"","tempRule":"default","swingRule":"default","fanRule":"default","isSchedule":false,"aSrc":"WEB","ts":1595806861,"deviceTypeVersion":"BP01","deviceType":"BREEZ-PLUS","light":"","rStatus":"","fwVersion":"1.0.6,2.3.8","exe":""},{"tempRange":"","turbo":"off","mid":"","mode":"cool","modeValue":"","temp":"24","tempValue":"","power":"off","swing":"auto","fanspeed":"high","scheduleID":"","macAddress":"BCDDC2339E37","applianceID":1880,"performedAction":"","performedActionValue":"","actualPower":"off","modeRule":"","tempRule":"","swingRule":"","fanRule":"","isSchedule":false,"aSrc":"WEB","ts":"","deviceTypeVersion":"","deviceType":"BREEZ-PLUS","light":"","rStatus":"","fwVersion":"","exe":""}],"I":2}'''

with requests.Session() as s:
	cookie_obj = requests.cookies.create_cookie(domain='smartcielo.com',name='returnUrl',value='/auth/login?r=s')
	s.cookies.set_cookie(cookie_obj)
	cookie_obj = requests.cookies.create_cookie(domain='smartcielo.com',name='_culture',value='en')
	s.cookies.set_cookie(cookie_obj)
	
#GET ENCRYPTED ACCESS TOKEN AND SESSION ID
	session_url = "https://smartcielo.com/auth/login"
	session_data = {
		'mobileDeviceName': 'chrome',
		'deviceTokenId': ip_address,
		'timeZone': '+03:00',
		'state': '',
		'client_id': '',
		'response_type': '',
		'scope': '',
		'redirect_uri': '',
		'userId': User_name,
		'password': Password,
		'rememberMe': 'false'
	}
	session_res = s.post(session_url, data = session_data)
  
#DECODING THE ENCRYPTED ACCESS TOKEN
	sessionId = s.cookies['ASP.NET_SessionId']
	soup = BeautifulSoup(session_res.text,"html.parser")
	S_id = soup.find('input', {'id': 'hdnAppUser'}).get('value')
	key = b'8080808080808080'
	iv = b'8080808080808080'
	ct = b64decode(S_id)
	cipher = AES.new(key, AES.MODE_CBC, iv)
	pt = unpad(cipher.decrypt(ct), AES.block_size)
	pt_decode =  (pt.decode())
	x = (str(pt, encoding='ascii', errors='ignore'))
	enc_data = json.loads(x)
	access_token_enc = (enc_data['accessToken'])
	access_token_enc_expire = (enc_data['expiresIn'])
		
#GET ACCESS TOKEN
	login_data = {'grant_type': 'password','username': User_name,'password': 'undefined'}
	login_url = "https://www.smartcielo.com/cAcc"
	r = s.post(login_url, data = login_data)
	r_Json = r.json()
	access_token = (r_Json['access_token'])
	token_type = (r_Json['token_type'])


#GET DEVICES LIST
	devices_url = 'https://smartcielo.com/api/device/initsubscription'
	devices_header = {'Authorization': token_type + ' ' + access_token}
	devices_data = {
        'accessToken': access_token_enc,
        'expiresIn': access_token_enc_expire,
        'sessionId': sessionId,
		'userID': User_name
	}	
	devices_list = s.post(devices_url, json = devices_data, headers = devices_header)
  #HERE IS A LIST OF YOUR DEVICES LISTED IN CIELO SMART WEBSITE YOU CAN GET ALL DATA FROM HERE IF YOU AREN'T SURE ABOUT MAC ADDRESS
	
  #GET CONNECTION TOKEN AND DATA FOR WEBSOCKET CONNECTION
	conID_url=	'https://smartcielo.com/signalr/negotiate'
	conID_data = {
		'clientProtocol': '1.5',
		'connectionData': '[{"name":"devicesactionhub"}]',
		'_: ': calendar.timegm(time.gmtime())
	}

	conID_res = s.get(conID_url, data = conID_data)
	jsonResponse = conID_res.json()
	conn_token = urllib.parse.quote(jsonResponse['ConnectionToken'],safe ='')
	conn_data = urllib.parse.quote('[{"name":"devicesactionhub"}]')

#WEBSOCKET START
	cookies = s.cookies.get_dict()
	ws_url = 'wss://smartcielo.com/signalr/connect?transport=webSockets&clientProtocol=1.5&connectionToken=' + conn_token + '&connectionData=' + conn_data + '&tid=5'
	
	def on_message(ws, message):
		print (message)
	def on_error(ws, error):
		print (error)
	def on_close(ws):
		print ("## closed ##")
	def on_open(ws):
		def run(*args):
			for i in range(3):
				time.sleep(1)
			time.sleep(1)
			ws.close()
		print("thread terminating...")
		thread.start_new_thread(run, ())
			
	if __name__ == "__main__":
		websocket.enableTrace(True)
		ws = create_connection(ws_url,
									on_message = on_message,
									on_error = on_error,
									on_close = on_close,
									cookie = "; ".join(["%s=%s" %(i, j) for i, j in cookies.items()]))
		ws.on_open = on_open
		result = ws.recv()
		print ("Received '%s'" % result)
		ws.send(json_data)
		result = ws.recv()
		print('Result: {}'.format(result))

		
