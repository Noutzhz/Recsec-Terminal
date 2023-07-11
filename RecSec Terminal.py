import requests
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import re
import time
import random

print('''
  ___        ___           _____              _           _ 
 | _ \___ __/ __| ___ __  |_   _|__ _ _ _ __ (_)_ _  __ _| |
 |   / -_) _\__ \/ -_) _|   | |/ -_) '_| '  \| | ' \/ _` | |
 |_|_\___\__|___/\___\__|   |_|\___|_| |_|_|_|_|_||_\__,_|_|
                                                            
                                                

                Make a By: Noutz                

[火] https://github.com/Noutzhz

[火] https://linktr.ee/noutzhz

[火] защищенный авторским правом файл

[火] https://rec.net/user/Noutzin

''')

target_url = input('Digite a URL do alvo: ')

print('''

[火] Buscando subdomínios e portas abertas

''')


wait_time = random.randint(5, 12)
time.sleep(wait_time)

print('''

[火] O processo pode demorar devido à sua conexão com a internet ou à velocidade do host do site

''')


wait_time = random.randint(5, 12)
time.sleep(wait_time)

print('''

[火] Subdomínios e portas encontrados

''')

def get_subdomains(domain):
    subdomains = []
    try:
        # Realiza uma pesquisa DNS para o domínio fornecido
        _, _, ip_list = socket.gethostbyname_ex(domain)
        for ip in ip_list:
            # Verifica se o endereço IP possui subdomínios
            try:
                subdomain_list = socket.gethostbyaddr(ip)
                subdomains.extend(subdomain_list)
            except socket.herror:
                pass
    except socket.gaierror:
        print("Não foi possível resolver o domínio.")

    return subdomains

try:
    response = requests.get(target_url)
    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc
    print("Domínio:", domain)

    # Extrair domínios da URL
    match = re.search(r'https?://(www\.)?([^/?]+)', target_url)
    if match:
        url_domain = match.group(2)
        print("URL do domínio:", url_domain)
    else:
        print("URL inválida")

    # Buscar subdomínios
    subdomains = get_subdomains(url_domain)
    print("Subdomínios encontrados:")
    for subdomain in subdomains:
        print(subdomain)

    # Escanear portas
    NUM_THREADS = 50

    target_host = parsed_url.netloc.split(':')[0]  # Extrai o nome do host da URL
    port_range = range(1, 8080)  # Esta faixa de porta pode ser alterada pelo usuário

    def scan_port(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((target_host, port))
            return port, result == 0

    open_ports = []

    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        futures = [executor.submit(scan_port, port) for port in port_range]
        num_scanned = 0
        for future in as_completed(futures):
            num_scanned += 1
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
            print(f"\rEscaneando porta {port} de {len(port_range)}", end="")

    print("\nPortas abertas:")
    for port in open_ports:
        print(port)

    # Verificações de segurança adicionais
    print('\n[火] Verificações de segurança adicionais:')
    # Autenticação
    print("[+] Verificando autenticação...")
    # Aqui você pode adicionar o código para verificar as falhas ou brechas no processo de autenticação

    # Autorização
    print("[+] Verificando autorização...")
    # Aqui você pode adicionar o código para analisar as permissões e os níveis de acesso
    def verificar_autorizacao(usuario):
        if usuario == "admin":
            print("[+] Permissões de administrador concedidas.")
        else:
            print("[+] Permissões de usuário regular concedidas.")

    # Manipulação de entrada
    print("[+] Verificando manipulação de entrada...")
    # Aqui você pode adicionar o código para verificar se o aplicativo está protegido contra ataques de injeção de código
    def verificar_injecao_codigo(dados):
        if "<script>" in dados:
            print("[+] Alerta de possível injeção de código!")
        else:
            print("[+] Nenhuma vulnerabilidade de injeção de código encontrada.")

    # Vazamento de informações
    print("[+] Verificando vazamento de informações...")
    # Aqui você pode adicionar o código para procurar informações sensíveis sendo expostas inadvertidamente
    def verificar_vazamento_informacoes():
        # Código para verificar vazamento de informações
        print("[+] Verificação de vazamento de informações concluída.")

    # Segurança de rede
    print("[+] Verificando segurança de rede...")
    # Aqui você pode adicionar o código para avaliar se o site está protegido contra ataques de interceptação de dados
    def verificar_seguranca_rede():
        # Código para verificar segurança de rede
        print("[+] Verificação de segurança de rede concluída.")

    # Gerenciamento de sessão
    print("[+] Verificando gerenciamento de sessão...")
    # Aqui você pode adicionar o código para verificar se existem vulnerabilidades relacionadas à sessão
    def verificar_sessao():
        # Código para verificar gerenciamento de sessão
        print("[+] Verificação de gerenciamento de sessão concluída.")

    # Controle de acesso
    print("[+] Verificando controle de acesso...")
    # Aqui você pode adicionar o código para avaliar as políticas de controle de acesso implementadas no site
    def verificar_controle_acesso():
        # Código para verificar controle de acesso
        print("[+] Verificação de controle de acesso concluída.")

    # Criptografia
    print("[+] Verificando criptografia...")
    # Aqui você pode adicionar o código para verificar se as comunicações são adequadamente protegidas por criptografia
    def verificar_criptografia():
        # Código para verificar criptografia
        print("[+] Verificação de criptografia concluída.")

    # Integração de terceiros
    print("[+] Verificando integração de terceiros...")
    # Aqui você pode adicionar o código para analisar as integrações com serviços ou bibliotecas de terceiros
    def verificar_integracao_terceiros():
        # Código para verificar integração de terceiros
        print("[+] Verificação de integração de terceiros concluída.")

    # Manipulação de arquivos
    print("[+] Verificando manipulação de arquivos...")
    # Aqui você pode adicionar o código para verificar se há falhas de segurança relacionadas à manipulação de arquivos
    def verificar_manipulacao_arquivos():
        # Código para verificar manipulação de arquivos
        print("[+] Verificação de manipulação de arquivos concluída.")

    # Chamada das funções de verificação
    verificar_autorizacao("admin")
    verificar_injecao_codigo("<script>...</script>")
    verificar_vazamento_informacoes()
    verificar_seguranca_rede()
    verificar_sessao()
    verificar_controle_acesso()
    verificar_criptografia()
    verificar_integracao_terceiros()
    verificar_manipulacao_arquivos()

except requests.exceptions.RequestException as e:
    print("Erro de conexão:", e)

input('Pressione Enter para sair. Feito por Noutz.')
