#!/usr/bin/env python
# -*- coding:utf-8 -*-

# CHECKWEB 2.0
# CHECKWEB es creado para reconocimiento de objetivos WEB
# este escript deberia ser usado antes de cualquier escaneo de vulnerabilidades a un sitio web
# Creacion 2018
# autor: @svelizdonoso
# git: https://github.com/SVelizDonoso


from copy import deepcopy
from urlparse import urljoin
from lxml.html import etree
import re
import os
import requests
import optparse
import sys
import urllib2
import random
import httplib
import socket 
import ssl
import argparse
from urlparse import urlparse
from optparse import OptionParser
import whois
from bs4 import BeautifulSoup
import json
from pprint import pprint
import dns.query
import dns.zone
import dns.resolver
import string
from IPy import IP
import urllib
import nmap
import builtwith

cwd, filename=  os.path.split(os.path.abspath(__file__))

#variables para el reporte

tracert =[]
chttpsec =[]
restwaf = []
destname = []
destaddr = []
fuente =""
getw = []
country =[]
addrdnsb = []
noaddrdnsb = []
tzone = []
tzone_err = []
bann = []
ptscan = []
tecnolog =[]

def banner():
    print """

	
	 ▄████▄   ██░ ██ ▓█████  ▄████▄   ██ ▄█▀ █     █░▓█████  ▄▄▄▄      
	▒██▀ ▀█  ▓██░ ██▒▓█   ▀ ▒██▀ ▀█   ██▄█▒ ▓█░ █ ░█░▓█   ▀ ▓█████▄    
	▒▓█    ▄ ▒██▀▀██░▒███   ▒▓█    ▄ ▓███▄░ ▒█░ █ ░█ ▒███   ▒██▒ ▄██   
	▒▓▓▄ ▄██▒░▓█ ░██ ▒▓█  ▄ ▒▓▓▄ ▄██▒▓██ █▄ ░█░ █ ░█ ▒▓█  ▄ ▒██░█▀     
	▒ ▓███▀ ░░▓█▒░██▓░▒████▒▒ ▓███▀ ░▒██▒ █▄░░██▒██▓ ░▒████▒░▓█  ▀█▓   
	░ ░▒ ▒  ░ ▒ ░░▒░▒░░ ▒░ ░░ ░▒ ▒  ░▒ ▒▒ ▓▒░ ▓░▒ ▒  ░░ ▒░ ░░▒▓███▀▒   
	  ░  ▒    ▒ ░▒░ ░ ░ ░  ░  ░  ▒   ░ ░▒ ▒░  ▒ ░ ░   ░ ░  ░▒░▒   ░    
	░         ░  ░░ ░   ░   ░        ░ ░░ ░   ░   ░     ░    ░    ░    
	░ ░       ░  ░  ░   ░  ░░ ░      ░  ░       ░       ░  ░ ░         
	░                       ░                                     ░  
                        Identificador de Seguridad Web para Pentester                                    

                                                           
    Developer: @svelizdonoso                                                      
    GitHub:    https://github.com/SVelizDonoso
    Correo:    cyslabs@gmail.com

    """

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'	

def Browsers():
	  br = [
                "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3",
		"Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)",
		"Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)",
		"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1",
		"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1",
		"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)",
		"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)",
		"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)",
		"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)",
		"Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)"
		]
	  user_agent = {'User-agent': random.choice(br) }
	  return user_agent

def getwhois(ip):
	r = requests.get("https://who.is/whois-ip/ip-address/"+ip)
	print "[*] Realizando Whois a Servidor: "+ip
	print ""
	if r.status_code == 200:
		#print r.text
		soup = BeautifulSoup(r.text,"lxml")
		res = soup.find('pre').getText()
		print res
		getw.append(res)
	print ""

def getinfoCountry(ip):
	r = requests.get("http://ip-api.com/json/"+ip)
	print "[*] Realizando Busqueda Pais: "+ip
	print ""
	if r.status_code == 200:
		data = json.loads(r.text)
		print "[*] Pais: " +data['country']
		print "[*] Ciudad: " +data['city']
		print "[*] Region: " +data['country']
		print "[*] Org: " +data['org']
		print "[*] Lat: " +str(data['lat'])
		print "[*] Lon: " +str(data['lon'])
		print ""
		country.append("Pais:" +data['country'])
		country.append("Ciudad:" +data['city'])
		country.append("Region:" +data['country'])
		country.append("Org:" +data['org'])
		country.append("Lat:" +str(data['lat']))
		country.append("Lon:" +str(data['lon']))

def getbruteDNS(url,tipo='S'):
	dicc = ""
	if tipo =='S':
		dicc = cwd +'/dic/subdomains-100.txt'
	if tipo =='M':
		dicc = cwd +'/dic/subdomains-500.txt'
	if tipo =="L":
		dicc = cwd +'/dic/subdomains-1000.txt'
	if tipo =='XL':
		dicc = cwd +'/dic/subdomains-10000.txt'
	
	div = url.split(".")
	if len(div) <= 2:
		dominio = url
	else:
		div.pop(0)
		dominio = ".".join(div)

	print "[*] Realizando Fuerza Bruta DNS.."
	print "[*] Espere un Momento..."
	print ""
	with open(dicc) as f:
	    for line in f:
		linedata = line.split('\n')
		try:
		  ip= socket.gethostbyname(linedata[0]+'.'+dominio)
		  print "[+] "+str(linedata[0]+'.'+dominio + " :" + ip + '' ) 
		  addrdnsb.append( str(linedata[0]+'.'+dominio)+":"+ str(ip) )
		except socket.error, msg:
		  noaddrdnsb.append( str(linedata[0]+'.'+dominio + ':No existe'))
	print ""
	
def transferZone(host):
	msj = ""
        div = host.split(".")
	if len(div) <= 2:
		hostname = host
	else:
		div.pop(0)
		hostname = ".".join(div)
	answers = dns.resolver.query(hostname,'NS')
	for server in answers:
		zona = ""
		try:
		   zona += "[*] Probando Transferecia Zona  " + str(server)
		   z = dns.zone.from_xfr(dns.query.xfr(str(server), host,timeout=1))
		   names = z.nodes.keys()
		   names.sort()
		   for n in names:
		      msj = z[n].to_text(n).split(" ")
		      #if msj[3] =="A":
		      print "[-] "+msj[0]+"."+host+":"+msj[1]+":"+msj[2]+":"+msj[3] +":"+ msj[4]  
		      tzone.append(msj[0]+"."+host+":"+msj[1]+":"+msj[2]+":"+msj[3] +":"+ msj[4])    
		   break
		except Exception, e:
		   zona += " , Error en el servidor! " 
		   tzone_err.append(zona)
		print zona
	print ""

def bannerHTTP(host):
        try:
		page = urllib.urlopen(host)
		resp =page.info()
	    	print "[*] Banner HTTP Completo: "
		print ""
	    	print str(resp)
	    	print ""
		bann.append(str(resp))
	except:
		bann.append("N/A")
		print "[*] Error al obtener banner del servidor!"

def tecnologHTTP(host):
	try:
		print "[*] Obteniendo Tecnologia Web: "
		print ""
		tecnologias = []
		i = 0
		a = builtwith.parse(host)
		for x in a:
	    		tecnologias.append(x)
		for z in tecnologias:
	    		for v in a[z]:
	       			print z + ":" + v
				tecnolog.append(z + ":" + v)
		print ""
	except:
		print "[*] Error al obtener Tecnologias del servidor!"
		tecnolog.append("N/A:N/A")

def portScan(host):
	try:
		print "[*] Realizando el Escaneo de Puertos con Nmap (TOP 1000)"
		print "Espere un momento......"
		print ""
		nmScan = nmap.PortScanner()
		nmScan.scan(str(host), arguments='-sV --min-parallelism 150 --max-parallelism 200 ')
	   	print "[*] Host: " + str(host)
	   	print "[*] Estado:"+ nmScan[str(host)]['status']['state']
	   	if nmScan[host].state() == "up":
	      		for port in nmScan[str(host)]['tcp']:
		  		thisDict = nmScan[str(host)]['tcp'][port]
		  		print str(host) + ':' + str(port) + ':' + thisDict['product'] + ':' + thisDict['version'] + ":" + thisDict['name'] +  ":" + thisDict['state'] + ":" + thisDict['extrainfo']
				ptscan.append(str(host) + ':' + str(port) + ':' + thisDict['product'] + ':' + thisDict['version'] + ":" + thisDict['name'] +  ":" + thisDict['state'] + ":" + thisDict['extrainfo'])
	except:
		print "[*] Error al obtener Puertos del servidor!"
		ptscan.append("N/A:N/A:N/A:N/A:N/A:N/A:N/A" )	  		

class SecurityHeaders():
    def __init__(self):
        pass

    def evaluate_warn(self, header, contents):

        warn = 1

        if header == 'x-frame-options':
            if contents.lower() in ['deny', 'sameorigin']:
                warn = 0
            else:
                warn = 1
    
        if header == 'strict-transport-security':
            warn = 0

        if header == 'content-security-policy':
            warn = 0

        if header == 'access-control-allow-origin':
            if contents == '*':
                warn = 1
            else:
                warn = 0
    
        if header == 'x-xss-protection':
            if contents.lower() in ['1', '1; mode=block']:
                warn = 0
            else:
                warn = 1

        if header == 'x-content-type-options':
            if contents.lower() == 'nosniff':
                warn = 0
            else:
                warn =1

        if header == 'x-powered-by' or header == 'server':
            if len(contents) > 1:
                warn = 1
            else: 
                warn = 0

        return {'defined': True, 'warn': warn, 'contents': contents}

    def test_https(self, url):
        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]
        sslerror = False
            
        conn = httplib.HTTPSConnection(hostname)
        try:
            conn.request('GET', '/')
            res = conn.getresponse()
        except socket.gaierror:
            return {'supported': False, 'certvalid': False}
        except ssl.CertificateError:
            return {'supported': True, 'certvalid': False}
        except:
            sslerror = True

        if sslerror:
            conn = httplib.HTTPSConnection(hostname, timeout=5, context = ssl._create_unverified_context() )
            try:
                conn.request('GET', '/')
                res = conn.getresponse()
                return {'supported': True, 'certvalid': False}
            except:
                return {'supported': False, 'certvalid': False}

        return {'supported': True, 'certvalid': True}

    def test_http_to_https(self, url, follow_redirects = 5):
        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]
        if not protocol:
            protocol = 'http' 

        if protocol == 'https' and follow_redirects != 5:
            return True
        elif protocol == 'https' and follow_redirects == 5:
            protocol = 'http'

        if (protocol == 'http'):
            conn = httplib.HTTPConnection(hostname)
        try:
            conn.request('HEAD', path)
            res = conn.getresponse()
            headers = res.getheaders()
        except socket.gaierror:
            print '[*] Fallo la Solicitud HTTP '
            return False

       
        if (res.status >= 300 and res.status < 400  and follow_redirects > 0):
            for header in headers:
                if (header[0] == 'location'):
                    return self.test_http_to_https(header[1], follow_redirects - 1) 

        return False

    def check_headers(self, url, follow_redirects = 0):
      
        retval = {
            'x-frame-options': {'defined': False, 'warn': 1, 'contents': '' },
            'strict-transport-security': {'defined': False, 'warn': 1, 'contents': ''},
            'access-control-allow-origin': {'defined': False, 'warn': 0, 'contents': ''},
            'content-security-policy': {'defined': False, 'warn': 1, 'contents': ''},
            'x-xss-protection': {'defined': False, 'warn': 1, 'contents': ''}, 
            'x-content-type-options': {'defined': False, 'warn': 1, 'contents': ''},
            'x-powered-by': {'defined': False, 'warn': 0, 'contents': ''},
            'server': {'defined': False, 'warn': 0, 'contents': ''} 
        }

        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]
        if (protocol == 'http'):
            conn = httplib.HTTPConnection(hostname)
        elif (protocol == 'https'):
               
                conn = httplib.HTTPSConnection(hostname, context = ssl._create_unverified_context() )
        else:
            
            return {}
    
        try:
            conn.request('HEAD', path)
            res = conn.getresponse()
            headers = res.getheaders()
        except socket.gaierror:
            print '[*] Fallo la Solicitud HTTP '
            return False

        if (res.status >= 300 and res.status < 400  and follow_redirects > 0):
            for header in headers:
                if (header[0] == 'location'):
                    return self.check_headers(header[1], follow_redirects - 1) 
                
        
        for header in headers:
            if (header[0] in retval):
                retval[header[0]] = self.evaluate_warn(header[0], header[1])

        return retval

LISTA_WAF = [
    '[*] Citrix NetScaler',
    '[*] Amazon CloudFront CDN',
    '[*] TrafficShield F5 Networks',
    '[*] ModSecurity',
    '[*] Sucuri WAF',
    '[*] 360',
    '[*] Safedog',
    '[*] NetContinuum',
    '[*] Anquanbao',
    '[*] Baidu Yunjiasu',
    '[*] Knownsec KS-WAF',
    '[*] BIG-IP',
    '[*] Barracuda',
    '[*] BinarySEC',
    '[*] BlockDos',
    '[*] Cisco ACE',
    '[*] CloudFlare',
    '[*] NetScaler',
    '[*] FortiWeb',
    '[*] jiasule',
    '[*] Newdefend',
    '[*] Palo Alto',
    '[*] Safe3WAF',
    '[*] Profense',
    '[*] West263CDN',
    '[*] WebKnight',
    '[*] Wallarm',
    '[*] USP Secure Entry Server',
    '[*] Radware AppWall',
    '[*] PowerCDN',
    '[*] Naxsi',
    '[*] Mission Control Application Shield',
    '[*] IBM WebSphere DataPower',
    '[*] Edgecast',
    '[*] Applicure dotDefender',
    '[*] Comodo WAF',
    '[*] ChinaCache-CDN',
    '[*] NSFocus'
]

WAF_PAYLOAD = (
                        "",
                        "search=<script>alert(1)</script>",
                        "file=../../../../../../etc/passwd",
                        "id=1 AND 1=1 UNION ALL SELECT 1,2,3,table_name FROM information_schema.tables WHERE 2>1--"
                     )




def listWaf():
	print "[*] Lista de WAF Soportados: "
        print " "
	for waf in LISTA_WAF:
		print waf



class whatwaf(object):
    def __init__(self,url):

        self._finger = ''
        self._nowaf = ''
        self._url = url
    def _run(self):
        try:
            self.scan_site()
        except:
            print "[+] Sitio Web a Auditar : " +self._url
            raise


    def scan_site(self):
        print "[+] Analizando Respuestas de Servidor WAF: " +self._url
	acum = 0
	resp = ""
	for payload in WAF_PAYLOAD:
            turl= ''
            turl = deepcopy(self._url)
            add_url = payload
            turl = urljoin(turl, add_url)

	    try:
                resp = requests.get(turl,headers = Browsers() ,allow_redirects=False)
	    except:
		 print "[+] Error al acceder al Servidor : " +self._url

            det = self.check_waf(resp)
	    if det > 0 :
		acum +=1
	if acum < 1 :
		print bcolors.OKGREEN + "[*] No se Detecto WAF en la Auditoria." + bcolors.ENDC
		print ""
		restwaf.append("No Se Detecto WAF")
	else:
	        print bcolors.WARNING + "[+] WAF Detectado : " + self._finger + bcolors.ENDC
		restwaf.append(self._finger)
                print ""
            

    def check_waf(self, resp):
	try:
        	self._xmlstr_dom = etree.parse(cwd+'/dic/fingerprinting.xml')
        	waf_doms = self._xmlstr_dom.xpath("waf")
        	detect = 0 
        	for waf_dom in waf_doms:
            		finger_dom = waf_dom.xpath("finger")
            		rule_dom = finger_dom[0].xpath("rule")
            		head_type =str(rule_dom[0].get("header").lower())
            		if head_type in resp.headers:
                 		regx = self.regexp_header(rule_dom,waf_dom,head_type,resp)
		 		if regx > 0 :
					detect +=1
		return detect
	except:
		print "[+] Error al obtener cabeceras del Servidor : " +self._url 	
           

    def regexp_header(self,rule_dom,waf_dom,head_type,resp):
            regmatch_dom = rule_dom[0].xpath("regmatch")
            regexp_doms = regmatch_dom[0].xpath("regexp") if regmatch_dom != None else []
            regexp = 0
            for regexp_dom in regexp_doms:
                exp_pattern = re.compile(regexp_dom.text)

                if exp_pattern.search(resp.headers[head_type]):
                   self._finger=waf_dom.get("name")
                   regexp += 1
            return regexp
                    
    
def initSecHttp(url,redirects=3):
	foo = SecurityHeaders()
	parsed = urlparse(url)
        print "[+] Auditoria Seguridad Header HTTP : " +str(url)
	print ""
	if not parsed.scheme:
        	url = 'http://' + url 
	headers = foo.check_headers(url, redirects)
	if not headers:
        	sys.exit(1)
		
	for header, value in headers.iteritems():
        	if value['warn'] == 1:
            		if value['defined'] == False:
                		print bcolors.FAIL+'[*] ' + header + '  ....[FAIL]'+bcolors.ENDC
				chttpsec.append(header+":"+""+":"+"FAIL")
            		else:
                		print bcolors.WARNING+'[*] ' + header + '  Valor:' + value['contents'] + ' ....[WARM]'+bcolors.ENDC
				chttpsec.append(header+":"+ value['contents']+":"+"WARM")
        	elif value['warn'] == 0:
            		if value['defined'] == False:
                		print bcolors.OKGREEN + '[*] ' + header + '  Cabecera Eliminada ......[OK]'+bcolors.ENDC
				chttpsec.append(header+":"+"Cabecera Eliminada"+":"+"OK")
            		else:
                		print bcolors.OKGREEN + '[*] ' + header + '  Valor:' + value['contents'] + ' .....[OK]'+bcolors.ENDC
				chttpsec.append(header+":"+value['contents']+":"+"OK")

	https = foo.test_https(url)
    	if https['supported']:
        	print bcolors.OKGREEN + '[*] Soporte de HTTPS  ...............[OK]'+bcolors.ENDC
		chttpsec.append("Soporte de HTTPS::OK")
    	else:
        	print bcolors.FAIL+'[*] Soporte de HTTPS  ....................[FAIL]'+bcolors.ENDC
		chttpsec.append("Soporte de HTTPS::FAIL")

	if https['certvalid']:
        	print bcolors.OKGREEN + '[*] Certificado HTTPS ...............[OK]'+bcolors.ENDC
		chttpsec.append("Certificado HTTPS::OK")
    	else:
        	print bcolors.FAIL+'[*] Certificado HTTPS ....................[FAIL]'+bcolors.ENDC
		chttpsec.append("Certificado HTTPS::FAIL")


    	if foo.test_http_to_https(url, 5):
        	print bcolors.OKGREEN + '[*] Redireccion HTTP -> HTTPS .......[OK]'+bcolors.ENDC
		chttpsec.append("Redireccion HTTP::OK")
    	else:
        	print bcolors.FAIL+'[*] Redireccion HTTP -> HTTPS  ...........[FAIL]'+bcolors.ENDC
		chttpsec.append("Redireccion HTTP::FAIL")
	print "\n"

def isPublic(host):
        tipo = ""
	ip = IP(host).iptype()
        if ip == "PRIVATE":
        	tipo = "IP PRIVADA"
	else:
		tipo ="IP PUBLICO"
	return tipo


def traceroute(dest_addr, max_hops=30, timeout=0.2):
    print "[*] Verificando Ruta del Servidor :"
    proto_icmp = socket.getprotobyname('icmp')
    proto_udp = socket.getprotobyname('udp')
    port = 33434

    for ttl in xrange(1, max_hops+1):
        rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto_icmp)
        rx.settimeout(timeout)
        rx.bind(('', port))
        tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto_udp)
        tx.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        tx.sendto('', (dest_addr, port))

        try:
            data, curr_addr = rx.recvfrom(512)
            curr_addr = curr_addr[0]
        except socket.error:
            curr_addr = None
        finally:
            rx.close()
            tx.close()

        yield curr_addr

        if curr_addr == dest_addr:
            break
def quitURL(dest_name):
	parsed = urlparse(dest_name)
        protocol = parsed[0]
        hostname = parsed[1]
        return hostname



def tableTracert(): 
        valor =""
        column = "<tr><td colspan='2'><h3>Tracert Route</h3></td></tr>"
	for f in tracert:
		valor = f.split(":")
		column += "<tr><td>"+valor[0]+"</td><td>"+valor[1]+"</td></tr>"
	table = "<table class='table table-bordered table-striped'>"+column+"</table>"
	return table

def tableSecHTTP():
        valor =""
        column = "<tr><td colspan='3'><h3>Cabeceras de Seguridad HTTP</h3></td></tr>"
	for f in chttpsec:
		valor = f.split(":")
		column += "<tr><td>"+valor[0]+"</td><td>"+valor[1]+"</td><td>"+valor[2]+"</td></tr>"
	table = "<table class='table table-bordered table-striped'>"+column+"</table>"
	return table

def tableWaf():
        valor =""
        column = "<tr><td colspan='2'><h3>Respuestas de Servidor WAF</h3></td></tr>"
	column += "<tr><td>Detecci&oacute;n WAF </td><td>"+str(restwaf[0])+"</td></tr>"
	table = "<table class='table table-bordered table-striped'>"+column+"</table>"
	return table

def tableTitulo(dns,ip):
        valor =""
        col = "<tr><td colspan='2'><h3>Servidor</h3></td></tr>"
	col += "<tr><td>DNS</td><td>"+str(dns)+"</td></tr>"
	col += "<tr><td>IP</td><td>"+str(ip)+"</td></tr>"
	table = "<table class='table table-bordered table-striped'>"+col+"</table>"
	return table

def tableWhois():
        valor =""
        col = "<tr><td><h3>Whois</h3></td></tr>"
	col += "<tr><td><pre>"+getw[0]+"</pre></td></tr>"
	table = "<table class='table table-bordered table-striped'>"+col+"</table>"
	return table

def tableBanner():
        valor =""
        col = "<tr><td><h3>Banner HTTP</h3></td></tr>"
	col += "<tr><td><pre>"+bann[0]+"</pre></td></tr>"
	table = "<table class='table table-bordered table-striped'>"+col+"</table>"
	return table

def tableCountry():
        valor =""
        column = "<tr><td colspan='2'><h3>Pais</h3></td></tr>"
	for f in country:
		valor = f.split(":")
		column += "<tr><td>"+valor[0]+"</td><td>"+valor[1]+"</td></tr>"
	table = "<table class='table table-bordered table-striped'>"+column+"</table>"
	return table

def tableBruteDNS():
        valor =""
        column = "<tr><td colspan='2'><h3>Fuerza Bruta DNS</h3></td></tr>"
	for f in addrdnsb:
		valor = f.split(":")
		column += "<tr><td>"+valor[0]+"</td><td>"+valor[1]+"</td></tr>"
	table = "<table class='table table-bordered table-striped'>"+column+"</table>"
	return table

def tabletecnologHTTP():
        valor =""
        column = "<tr><td colspan='2'><h3>Tecnologias</h3></td></tr>"
	for f in tecnolog:
		valor = f.split(":")
		column += "<tr><td>"+valor[0]+"</td><td>"+valor[1]+"</td></tr>"
	table = "<table class='table table-bordered table-striped'>"+column+"</table>"
	return table

def tablePScan():
        valor =""
        column = "<tr><td colspan='7'><h3>Escaneo Puertos</h3></td></tr>"
	for f in ptscan:
	    valor = f.split(":")
	    column += "<tr><td>"+valor[0]+"</td><td>"+valor[1]+"</td><td>"+valor[3]+"</td><td>"+valor[3]+"</td><td>"+valor[4]+"</td><td>"+valor[5]+"</td><td>"+valor[6]+"</td></tr>"
	    table = "<table class='table table-bordered table-striped'>"+column+"</table>"
	return table

def tableTZone():
        valor =""
        column = "<tr><td colspan='5'><h3>Transferencia de Zona DNS</h3></td></tr>"
	if not tzone:
		for err in tzone_err:
			column += "<tr><td colspan='5'>"+err+"</td></tr>"
		table = "<table class='table table-bordered table-striped'>"+column+"</table>"
	else:
		for f in tzone:
			valor = f.split(":")
			column += "<tr><td>"+valor[0]+"</td><td>"+valor[1]+"</td><td>"+valor[3]+"</td><td>"+valor[3]+"</td><td>"+valor[4]+"</td></tr>"
		table = "<table class='table table-bordered table-striped'>"+column+"</table>"
	return table

def htmlBody(cod):
	html ="""
		<!DOCTYPE html>
		<html lang="es">
		<head>
		  <title>CheckWeb</title>
		  <meta charset="utf-8">
		  <meta autor"@svelizdonoso">
		  <meta name="viewport" content="width=device-width, initial-scale=1">
		  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
		  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
  		  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
		</head>
		<body >
			<div class="container" id='content'>
				<div class="jumbotron">
				  <h1 class="display-4">CheckWeb</h1>
				  <p class="lead">Identificador de Seguridad Web para Pentester</p>
				</div>
		          
  			        """+cod+"""
			</div>
		        <div class="footer">
  			    <center><p>CheckWeb 2.0 2018 - Developer @svelizdonoso </p></center>
		       </div>
		</body>
		</html>

	"""
	return html

def CreateReport(filename,content):
	file = open(filename, "w")
	file.write(content)
	file.close()
	print "[*] Reporte Creado con Exito! :"+filename
	print "\n\n"
	
def getServer(url):
	try:
		dest_name = str(quitURL(res.url))
	    	dest_addr = socket.gethostbyname(dest_name)
		destaddr.append(str(dest_addr))
		destname.append(dest_name)
	    	print "[+] DNS: " + destname[0]
		print "[+] IP : "+ destaddr[0]
		print ""
	except:
		print "[*] Error al acceder al dominio "+url
		sys.exit(1)
		

def help():
	parser = argparse.ArgumentParser()
	parser.add_argument('-u','--url', action='store', dest='url',help='URL del Servidor')
	parser.add_argument('-waf','--waff', action='store_true', dest='waf',help='Detectar Proteccion deWAF')
	parser.add_argument('-sec','--httpsec', action='store_true', dest='hsec',help='Seguridad cabeceras HTTP')
	parser.add_argument('-w', '--whois',action='store_true', dest='whois',help='Obtener Informacion publica Dominio')
	parser.add_argument('-c', '--country',action='store_true', dest='country',help='Obtener Informacion Pais')
	parser.add_argument('-b', '--banner',action='store_true', dest='banner',help='Obtener Banner HTTP')
	parser.add_argument('-bru', '--dnsbrute', action='store',dest='brute',help='Fuerza Bruta DNS')
	parser.add_argument('-tz', '--tzone',  dest='tzone',action='store_true',help='Transferencia de Zona DNS')
        parser.add_argument('-t', '--tracert',action='store_true', dest='tracert',help='Determinar la ruta que toma un paquete para alcanzar su destino. ')
	parser.add_argument('-tec', '--tecnologia',action='store_true', dest='tec',help='Obtener Tecnologia Web Usada ')
	parser.add_argument('-pscan', '--portscan',action='store_true', dest='pscan',help='Escaneo de Puertos Top 1000. ')
	parser.add_argument('-r', '--reporte',action='store', dest='reporte',help='Crea reporte HTML del Objetivo. ')
	parser.add_argument('-l', '--list',action='store_true', dest='list',help='Waf Soportados por el script')
	parser.add_argument('--version', action='version', version='%(prog)s 1.0')
        return parser



if __name__ == '__main__':
    banner()
    results = help()
    res = results.parse_args()

    if res.list:
        listWaf()
	print "\n\n"
        sys.exit()
    if res.url !=None and res.url !="":
	getServer(res.url)
	fuente +=tableTitulo(destname[0],destaddr[0])
    if res.whois:
	getwhois(destaddr[0])
	fuente += tableWhois()
    if res.country:
	getinfoCountry(destaddr[0])
	fuente += tableCountry()
    if res.brute !=None and res.brute !="":
	getbruteDNS(destname[0],res.brute)
	fuente += tableBruteDNS()
    if res.tzone:
	transferZone(destname[0])
	fuente += tableTZone()
    if res.waf:
	wafidentify = whatwaf(res.url)
        wafidentify._run()
	fuente += tableWaf()
    if res.tracert== True :
	dest_name = str(quitURL(res.url))
    	dest_addr = socket.gethostbyname(dest_name)
    	for i, v in enumerate(traceroute(dest_addr)):
        	print "[-] %d\t%s" % (i+1, v)
		tracert.append(str(i+1)+":"+ str(v))
	print ""
	fuente += tableTracert()
    if res.banner ==True:
	bannerHTTP(res.url)
	fuente += tableBanner()
    if res.tec ==True:
	tecnologHTTP(res.url)
	fuente += tabletecnologHTTP()
    if res.pscan ==True:
	dest_name = str(quitURL(res.url))
        dest_addr = socket.gethostbyname(dest_name)
	portScan(str(dest_addr))
	fuente += tablePScan()
    if res.hsec == True :
	try:
		initSecHttp(res.url)
		fuente += tableSecHTTP()
	except:
		print "[*] No se pudo Obtener Cabeceras de Seguridad!"
    if res.url == None or res.url == "":
        results.print_help()
        sys.exit()  
    if res.reporte:
	    CreateReport(res.reporte,htmlBody(fuente))    
    else:
        sys.exit()
