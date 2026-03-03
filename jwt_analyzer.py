import argparse
import base64
import datetime as dt
import hmac
import hashlib
import json
import re
import sys
import math
from typing import Any, Dict, Optional, Tuple, List
from colorama import init, Fore, Style, Back

# Inicializa colorama
init()

# Regex para validação Base64URL
B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")

# Mapeamento de algoritmos
HS_ALGORITHMS = {"HS256", "HS384", "HS512"}
RS_ALGORITHMS = {"RS256", "RS384", "RS512"}
ES_ALGORITHMS = {"ES256", "ES384", "ES512"}
CRITICAL_ALGS = {"none", "None", "NONE", "HS256"}


class JWTAnalyzer:
    def __init__(self, token: str, secret: Optional[str] = None):
        self.token = token.strip()
        self.secret = secret
        self.header: Dict[str, Any] = {}
        self.payload: Dict[str, Any] = {}
        self.signature: str = ""
        self.issues: List[Dict[str, str]] = []
        self.info: List[str] = []

    def analyze(self) -> Dict[str, Any]:
        """Executa a análise completa do JWT."""
        try:
            self._parse_token()
            self._check_header_security()
            self._check_payload_security()
            self._check_signature_strength()
            
            if self.secret:
                self._verify_signature()

            return self._build_report()
        except Exception as e:
            return {"error": str(e)}

    def _parse_token(self):
        """Decodifica e parseia as partes do token."""
        parts = self.token.split(".")
        if len(parts) != 3:
            raise ValueError("JWT inválido: deve conter 3 partes separadas por '.'")
        
        try:
            self.header = self._decode_segment(parts[0])
            self.payload = self._decode_segment(parts[1])
            self.signature = parts[2]
        except Exception as e:
            raise ValueError(f"Erro ao decodificar JWT: {e}")

    def _decode_segment(self, segment: str) -> Dict[str, Any]:
        """Decodifica segmento Base64URL para JSON."""
        if not B64URL_RE.match(segment):
            raise ValueError("Segmento contém caracteres Base64URL inválidos")
        
        # Adiciona padding
        pad = "=" * (-len(segment) % 4)
        try:
            decoded = base64.urlsafe_b64decode(segment + pad)
            obj = json.loads(decoded.decode("utf-8"))
            if not isinstance(obj, dict):
                raise ValueError("Segmento deve ser um objeto JSON")
            return obj
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON inválido: {e}")
        except Exception as e:
            raise ValueError(f"Erro no decode: {e}")

    def _check_header_security(self):
        """Verifica vulnerabilidades no header."""
        alg = str(self.header.get("alg", "")).upper()
        typ = self.header.get("typ")
        kid = self.header.get("kid")
        jku = self.header.get("jku")
        jwk = self.header.get("jwk")
        x5u = self.header.get("x5u")

        # Checks críticos
        if alg == "NONE":
            self._add_issue("CRITICAL", "alg_none", "Algoritmo 'none' detectado. Permite bypass de assinatura.")
        
        if alg.startswith("HS") and any(self.header.get(k) for k in ["jwk", "jku", "x5u"]):
            self._add_issue("HIGH", "alg_confusion", "Algoritmo HS com chaves públicas. Risco de Algorithm Confusion Attack.")

        if jku:
            self._add_issue("HIGH", "jku_present", f"Cabeçalho 'jku' presente ({jku}). Vetor de ataque comum.")
        
        if jwk:
            self._add_issue("MEDIUM", "jwk_present", "Chave pública embutida no token ('jwk').")

        if kid:
            self._add_issue("INFO", "kid_present", "Claim 'kid' presente. Verificar se é suscetível a SQLi/Path Traversal.")
        
        if typ and str(typ).lower() != "jwt":
            self._add_issue("LOW", "typ_unusual", f"Tipo incomum: {typ}")

    def _check_payload_security(self):
        """Verifica vulnerabilidades e boas práticas no payload."""
        now = dt.datetime.now(tz=dt.timezone.utc)
        
        # Claims de tempo
        exp = self.payload.get("exp")
        nbf = self.payload.get("nbf")
        iat = self.payload.get("iat")

        if exp is None:
            self._add_issue("MEDIUM", "exp_missing", "Sem claim 'exp'. Token não expira (risco de replay).")
        else:
            try:
                exp_dt = dt.datetime.fromtimestamp(int(exp), tz=dt.timezone.utc)
                if exp_dt < now:
                    delta = now - exp_dt
                    self._add_issue("INFO", "exp_expired", f"Token EXPIRADO há {delta}")
                else:
                    delta = exp_dt - now
                    self.info.append(f"Token válido por mais: {delta}")
            except Exception:
                self._add_issue("HIGH", "exp_invalid", f"Claim 'exp' inválido: {exp}")

        if nbf:
            try:
                nbf_dt = dt.datetime.fromtimestamp(int(nbf), tz=dt.timezone.utc)
                if nbf_dt > now:
                    self._add_issue("INFO", "nbf_future", f"Token ainda não válido (nbf: {nbf_dt})")
            except Exception:
                self._add_issue("LOW", "nbf_invalid", f"Claim 'nbf' inválido: {nbf}")

        # Claims de identidade
        for claim in ["iss", "aud", "sub"]:
            if claim not in self.payload:
                self._add_issue("LOW", f"{claim}_missing", f"Claim '{claim}' ausente. Validação recomendada.")

        # Dados sensíveis
        sensitive_keys = ["password", "secret", "key", "token", "credit", "card", "ssn", "cpf"]
        for key in self.payload.keys():
            if any(s in key.lower() for s in sensitive_keys):
                self._add_issue("HIGH", "sensitive_data", f"Dados sensíveis potencialmente expostos: '{key}'")

        # Roles/Scopes
        if any(k in self.payload for k in ["role", "roles", "scope", "scopes"]):
            self.info.append("Claims de autorização presentes. Verificar enforcement no servidor.")

    def _check_signature_strength(self):
        """Analisa a entropia da assinatura."""
        if not self.signature:
            return
        
        # Entropia de Shannon simples
        sig_len = len(self.signature)
        unique_chars = len(set(self.signature))
        
        if sig_len < 20:
            self._add_issue("MEDIUM", "weak_signature", f"Assinatura curta ({sig_len} chars). Pode ser fraca.")
        
        # Heurística simples de entropia
        if unique_chars < 10 and sig_len > 10:
            self._add_issue("LOW", "low_entropy", "Baixa diversidade de caracteres na assinatura.")

    def _verify_signature(self):
        """Verifica assinatura HMAC se segredo fornecido."""
        alg = str(self.header.get("alg", "")).upper()
        
        if alg not in HS_ALGORITHMS:
            self._add_issue("ERROR", "verify_failed", f"Algoritmo {alg} não suportado para verificação HS.")
            return

        try:
            header_b64, payload_b64, _ = self.token.split(".")
            signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
            sig = self._b64url_decode(self.signature)

            digestmod = {
                "HS256": hashlib.sha256,
                "HS384": hashlib.sha384,
                "HS512": hashlib.sha512
            }[alg]

            expected = hmac.new(self.secret.encode("utf-8"), signing_input, digestmod).digest()
            
            if hmac.compare_digest(expected, sig):
                self.info.append(f"✅ Assinatura {alg} VALIDADA com sucesso.")
            else:
                self._add_issue("CRITICAL", "signature_invalid", "Assinatura HMAC INVÁLIDA para o segredo fornecido.")
        except Exception as e:
            self._add_issue("ERROR", "verify_error", f"Erro na verificação: {e}")

    def _b64url_decode(self, data: str) -> bytes:
        pad = "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + pad)

    def _add_issue(self, severity: str, code: str, message: str):
        self.issues.append({"severity": severity, "code": code, "message": message})

    def _build_report(self) -> Dict[str, Any]:
        return {
            "header": self.header,
            "payload": self.payload,
            "issues": self.issues,
            "info": self.info,
            "summary": {
                "total_issues": len(self.issues),
                "critical": len([i for i in self.issues if i["severity"] == "CRITICAL"]),
                "high": len([i for i in self.issues if i["severity"] == "HIGH"])
            }
        }


def print_report(report: Dict[str, Any], raw: bool = False):
    """Imprime o relatório formatado no console."""
    if "error" in report:
        print(f"\n{Fore.RED}[!] Erro: {report['error']}{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}           JWT ANALYZER REPORT{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")

    if raw:
        print(f"{Fore.WHITE}[Raw Token]{Style.RESET_ALL}")
        print(f"{report.get('header_b64', 'N/A')}.{report.get('payload_b64', 'N/A')}.{report.get('sig_b64', 'N/A')}\n")

    print(f"{Fore.BLUE}[Header]{Style.RESET_ALL}")
    print(json.dumps(report["header"], indent=2, sort_keys=True))
    print()

    print(f"{Fore.BLUE}[Payload]{Style.RESET_ALL}")
    print(json.dumps(report["payload"], indent=2, sort_keys=True))
    print()

    if report["info"]:
        print(f"{Fore.GREEN}[Info]{Style.RESET_ALL}")
        for msg in report["info"]:
            print(f"  ℹ️  {msg}")
        print()

    if report["issues"]:
        print(f"{Fore.RED}[Security Issues]{Style.RESET_ALL}")
        # Ordena por severidade
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_issues = sorted(report["issues"], key=lambda x: severity_order.get(x["severity"], 5))
        
        for issue in sorted_issues:
            color = {
                "CRITICAL": Fore.RED + Back.WHITE,
                "HIGH": Fore.RED,
                "MEDIUM": Fore.YELLOW,
                "LOW": Fore.WHITE,
                "INFO": Fore.CYAN,
                "ERROR": Fore.RED
            }.get(issue["severity"], Fore.WHITE)
            
            print(f"  {color}[{issue['severity']}]{Style.RESET_ALL} {issue['code']}: {issue['message']}")
    else:
        print(f"{Fore.GREEN}[Security Issues] Nenhum problema óbvio detectado.{Style.RESET_ALL}")
    
    print()
    summary = report["summary"]
    if summary["critical"] > 0 or summary["high"] > 0:
        print(f"{Fore.RED}⚠️  Atenção: {summary['critical']} Crítico(s), {summary['high']} Alto(s){Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}✓  Sem issues críticos/altos.{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")


def main():
    ap = argparse.ArgumentParser(
        description="JWT Analyzer (AppSec Helper)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  %(prog)s <token>
  %(prog)s <token> --verify-hs-secret "minha_chave_secreta"
  %(prog)s <token> -o output.json
  %(prog)s <token> --raw
        """
    )
    ap.add_argument("token", help="JWT string (header.payload.signature)")
    ap.add_argument("--verify-hs-secret", "-s", help="Segredo para verificar assinatura HS*")
    ap.add_argument("--raw", "-r", action="store_true", help="Mostrar segmentos Base64 raw")
    ap.add_argument("--output", "-o", help="Salvar relatório em JSON")
    ap.add_argument("--quiet", "-q", action="store_true", help="Somente output JSON (sem console)")

    args = ap.parse_args()

    analyzer = JWTAnalyzer(args.token, args.verify_hs_secret)
    report = analyzer.analyze()

    # Adiciona dados raw se necessário
    if args.raw or args.output:
        parts = args.token.split(".")
        report["header_b64"] = parts[0]
        report["payload_b64"] = parts[1]
        report["sig_b64"] = parts[2]

    # Saída
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        if not args.quiet:
            print(f"{Fore.GREEN}[✓] Relatório salvo em: {args.output}{Style.RESET_ALL}")
    
    if not args.quiet:
        print_report(report, raw=args.raw)

    # Exit code baseado em severidade
    if report.get("summary", {}).get("critical", 0) > 0:
        sys.exit(2)
    elif report.get("summary", {}).get("high", 0) > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
