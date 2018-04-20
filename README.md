# CheckWeb

<img src="https://image.ibb.co/m7SBU7/checkweb.png" >

# Descripción

CheckWeb es una herramienta que utiliza varias técnicas para investigar y recolectar, toda la información necesaria de un objetivo antes de planificar un Pentesting Web, la idea es que CheckWeb, ayude a pentester de habla hispana a agilizar sus tareas y no perder tiempo en ejecutar varias herramientas por separado.

# Funcionalidades

CheckWeb está pensado para auditar aplicaciones web en los siguientes ámbitos:

- Buscar en la base de datos de Internet (Whois)
- Buscar país y ciudad donde residen los servidores
- Buscar nombres de dominios
- Buscar información de contacto
- Buscar toda la información que se pueda extraer de los DNS
- Fuerza Bruta DNS
- Transferencia de Zona DNS
- Banner Grabbing
- IP Traceroute
- Cabeceras de Seguridad HTTP
- Detección de WAF
- Tecnología Utilizada HTTP
- Escaneo de Puertos con Nmap

# Soporte
Por el momento Checkweb soporta OS Linux

# Dependencias
Antes de ejecutar el script asegúrate de que estén instaladas las dependencias necesarias en tu Linux

```sh
pip install deepcopy
pip install urlparse2
pip install requests
pip install python-whois
pip install python-nmap
pip install dnspython
pip install IPy
pip install BeautifulSoup
pip install builtwith
```

# Instalación
```sh
git clone https://github.com/SVelizDonoso/checkweb.git
cd checkweb
python checkweb.py
```
# Opciones
```sh
python checkweb.py

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

    
usage: wafid.py [-h] [-u URL] [-waf] [-sec] [-w] [-c] [-b] [-bru BRUTE]
                [-tz TZONE] [-t] [-tec] [-pscan] [-r REPORTE] [-l] [--version]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     URL del Servidor
  -waf, --waff          Detectar Proteccion deWAF
  -sec, --httpsec       Seguridad cabeceras HTTP
  -w, --whois           Obtener Informacion publica Dominio
  -c, --country         Obtener Informacion Pais
  -b, --banner          Obtener Banner HTTP
  -bru BRUTE, --dnsbrute BRUTE 
                        Fuerza Bruta DNS
  -tz TZONE, --tzone TZONE
                        Transferencia de Zona DNS
  -t, --tracert         Determinar la ruta que toma un paquete para alcanzar
                        su destino.
  -tec, --tecnologia    Obtener Tecnologia Web Usada
  -pscan, --portscan    Escaneo de Puertos Top 1000.
  -r REPORTE, --reporte REPORTE
                        Crea reporte HTML del Objetivo.
  -l, --list            Waf Soportados por el script
  --version             show program's version number and exit

```

# Lista de Waf Soportados

```sh
python checkweb.py --list
    
[*] Lista de WAF Soportados: 
 
[*] Citrix NetScaler
[*] Amazon CloudFront CDN
[*] TrafficShield F5 Networks
[*] ModSecurity
[*] Sucuri WAF
[*] 360
[*] Safedog
[*] NetContinuum
[*] Anquanbao
[*] Baidu Yunjiasu
[*] Knownsec KS-WAF
[*] BIG-IP
[*] Barracuda
[*] BinarySEC
[*] BlockDos
[*] Cisco ACE
[*] CloudFlare
[*] NetScaler
[*] FortiWeb
[*] jiasule
[*] Newdefend
[*] Palo Alto
[*] Safe3WAF
[*] Profense
[*] West263CDN
[*] WebKnight
[*] Wallarm
[*] USP Secure Entry Server
[*] Radware AppWall
[*] PowerCDN
[*] Naxsi
[*] Mission Control Application Shield
[*] IBM WebSphere DataPower
[*] Edgecast
[*] Applicure dotDefender
[*] Comodo WAF
[*] ChinaCache-CDN
[*] NSFocus
```
# Uso de la Herramienta
```sh

python checkweb.py -u=https://www.microsoft.com -waf -sec -w -c -b -t -tec -pscan -brut=S -tz=microsoft.com -r=/tmp/reporte.htm

```
# Ajustes de Fuerza bruta DNS
```sh
--dnsbrute=S o -bru=S    SMALL Lista 150 subdominios 
--dnsbrute=M o -bru=M    MEDIUM diccionario 500 subdominios
--dnsbrute=L o -bru=L    LARGE diccionario 1.000 subdominios
--dnsbrute=XL o -bru=XL  XLARGE diccionario 10.000 subdominios
```

# Video
[![Demo CheckWeb](https://s1.gifyu.com/images/checkweb.md.gif)] <br>
[Video Checkweb ]https://gifyu.com/image/sGUx

# Advertencia
Este software se creo SOLAMENTE para fines educativos. No soy responsable de su uso. Úselo con extrema precaución.

# Autor
@sveliz https://github.com/SVelizDonoso/

# Reporte HTML Demo
 https://svelisdonoso.github.com/checkweb/reporte.html


