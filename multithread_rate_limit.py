import threading
import requests

# Função que será executada por cada thread
def send_request(url, thread_id):
    try:
        response = requests.get(url)
        print(f'Thread {thread_id}: {response.status_code}')
    except Exception as e:
        print(f'Thread {thread_id}: Erro ao fazer a requisição - {e}')

# Função para iniciar múltiplas threads
def test_rate_limit(url, num_threads):
    threads = []

    # Criando as threads
    for i in range(num_threads):
        thread = threading.Thread(target=send_request, args=(url, i))
        threads.append(thread)
    
    # Iniciando todas as threads
    for thread in threads:
        thread.start()

    # Aguardando todas as threads terminarem
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    url = "https://exemplo.com/api/teste"  # Altere para a URL que você quer testar
    num_threads = 20  # Número de threads (ou requisições simultâneas)
    
    test_rate_limit(url, num_threads)
