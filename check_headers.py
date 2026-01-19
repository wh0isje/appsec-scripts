import requests

url = "URL"
response = requests.get(url)

headers_to_check = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection"
]

for header in headers_to_check:
    if header in response.headers:
        print(f"{header}: {response.headers[header]}")
    else:
        print(f"{header} is missing")
