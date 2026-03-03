import socket
import argparse
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from colorama import init, Fore, Style

#Inicializa o colorama para funcionar no Windows
init()

#Configuração de Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("scan_log.txt"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

#Dicionário de Serviços e Riscos Potenciais
PORT_SERVICES = {
    21: ("FTP", "Transferência de arquivos (Credenciais em texto claro)"),
    22: ("SSH", "Acesso remoto seguro (Risco de Força Bruta)"),
    23: ("Telnet", "Acesso remoto inseguro (Sem criptografia)"),
    25: ("SMTP", "Servidor de E-mail (Risco de Relay Aberto)"),
    53: ("DNS", "Servidor de Nomes (Risco de Amplificação)"),
    80: ("HTTP", "Servidor Web (Risco de XSS/Injection)"),
    110: ("POP3", "Recebimento de E-mail (Credenciais em texto claro)"),
    443: ("HTTPS", "Servidor Web Seguro (Verificar TLS/SSL)"),
    3306: ("MySQL", "Banco de Dados (Exposição Direta)"),
    3389: ("RDP", "Área de Trabalho Remota (Risco de Brute-force)"),
    8080: ("HTTP-Alt", "Servidor Web Alternativo (Frequentemente Painéis)"),
    5432: ("PostgreSQL", "Banco de Dados (Exposição Direta)"),
}

class PortScanner:
    def __init__(self, host, ports, timeout=1, threads=10):
        self.host = host
        self.ports = ports
        self.timeout = timeout
        self.threads = threads
        self.print_lock = Lock()
        self.open_ports = []

    def resolve_host(self):
        """Tenta resolver o IP a partir do domínio."""
        try:
            ip = socket.gethostbyname(self.host)
            logger.info(f"Alvo resolvido: {self.host} -> {ip}")
            return ip
        except socket.gaierror:
            logger.error(f"Não foi possível resolver o hostname: {self.host}")
            sys.exit(1)

    def scan_port(self, port):
        """Verifica uma porta específica e tenta pegar o banner."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.host, port))
                
                if result == 0:
                    service_info = PORT_SERVICES.get(port, ("Desconhecido", "N/A"))
                    banner = self.get_banner(s)
                    
                    msg = f"[ABERTA] {port}/{service_info[0]} | {service_info[1]}"
                    if banner:
                        msg += f" | Banner: {banner.strip()}"
                    
                    with self.print_lock:
                        print(f"{Fore.GREEN}{msg}{Style.RESET_ALL}")
                        logger.info(f"Porta {port} aberta. Serviço: {service_info[0]}")
                    
                    self.open_ports.append(port)
        except Exception as e:
            logger.debug(f"Erro na porta {port}: {e}")

    def get_banner(self, sock):
        """Tenta ler o banner do serviço."""
        try:
            sock.settimeout(0.5)
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            return banner
        except:
            return None

    def run(self):
        """Executa o scan multithreaded."""
        logger.info(f"Iniciando scan em {self.host} com {len(self.ports)} portas...")
        print(f"\n{Fore.CYAN}--- Iniciando Scan em {self.host} ---{Style.RESET_ALL}\n")

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_port = {executor.submit(self.scan_port, port): port for port in self.ports}
                
                for future in as_completed(future_to_port):
                    pass 
            
            print(f"\n{Fore.CYAN}--- Scan Finalizado ---{Style.RESET_ALL}")
            print(f"Portas abertas encontradas: {len(self.open_ports)}")
            
            if self.open_ports:
                print(f"{Fore.YELLOW}Dica: Investigue as versões dos serviços nas portas abertas.{Style.RESET_ALL}")

        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Scan interrompido pelo usuário.{Style.RESET_ALL}")
            sys.exit(0)

def main():
    #Configuração dos argumentos de linha de comando
    parser = argparse.ArgumentParser(description="Scanner de Portas Multithread (Uso Educacional)")
    parser.add_argument("target", help="IP ou Domínio do alvo")
    parser.add_argument("-p", "--ports", type=str, default="common", help="Portas (ex: 21,22,80 ou 'common')")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Número de threads (padrão: 10)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout do socket em segundos")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verbose")

    args = parser.parse_args()

    #Definir lista de portas
    if args.ports == "common":
        port_list = list(PORT_SERVICES.keys())
    else:
        try:
            port_list = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            logger.error("Formato de porta inválido. Use números separados por vírgula.")
            sys.exit(1)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    scanner = PortScanner(
        host=args.target, 
        ports=port_list, 
        timeout=args.timeout, 
        threads=args.threads
    )
    
    #Resolver DNS antes de começar
    scanner.host = scanner.resolve_host()
    scanner.run()

if __name__ == "__main__":
    main()
