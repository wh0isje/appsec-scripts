import socket
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored

# Dicionário com portas e vulnerabilidades conhecidas
PORTS_AND_VULNERABILITIES = {
    21: "FTP - Senhas em texto claro",
    22: "SSH - Força bruta",
    23: "Telnet - Sem criptografia",
    25: "SMTP - Relay aberto",
    53: "DNS - Amplificação de DDoS",
    80: "HTTP - Vulnerabilidades XSS",
    110: "POP3 - Credenciais em texto claro",
    443: "HTTPS - Problemas de TLS",
    3306: "MySQL - Configuração padrão fraca",
    3389: "RDP - Acesso remoto inseguro"
}

def scan_port(host, port):
    """
    Verifica se uma porta está aberta no host.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            if result == 0:
                if port in PORTS_AND_VULNERABILITIES:
                    print(colored(f"[ABERTA] Porta {port}: {PORTS_AND_VULNERABILITIES[port]}", "green"))
                else:
                    print(colored(f"[ABERTA] Porta {port}: Nenhuma vulnerabilidade conhecida associada", "green"))
            else:
                print(f"[FECHADA] Porta {port}")
    except Exception as e:
        print(f"Erro ao verificar a porta {port}: {e}")

def main():
    print("\nBem-vindo ao Scanner de Portas")
    host = input("Digite o endereço IP ou domínio a ser escaneado: ")
    
    # Lista de portas comuns
    common_ports = list(PORTS_AND_VULNERABILITIES.keys())
    
    # Pool de threads para escaneamento
    print("\nIniciando scan...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        for port in common_ports:
            executor.submit(scan_port, host, port)
    
    print("\nScan finalizado.")

if __name__ == "__main__":
    main()