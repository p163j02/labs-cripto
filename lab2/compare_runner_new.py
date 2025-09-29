#!/usr/bin/env python3
"""
compare_runner_new.py

Orquesta y compara 3 (o 4) métodos de fuerza bruta sobre DVWA:
 - Hydra (si está instalado)
 - bruteforce_get_stream.py (streaming, threads)
 - bruteforce_get_threaded.py (carga lista en memoria)
 - curl_loop.sh (single-thread curl loop)

Genera:
 - runs/<tool>_<runnum>/   (salidas crudas)
 - comparison_new_results.csv  (resumen con mean/std/time)
 - logs/ (stdout/stderr por run)

USO:
  python3 compare_runner_new.py
Opciones dentro del script: NUM_RUNS, TIMEOUT, PATHS
"""

import subprocess
import time
import os
import csv
import shutil
import statistics
import sys

# ---------- CONFIGURACIÓN ----------
NUM_RUNS = 3  # cuantas veces repetir cada herramienta
TIMEOUT = 1800  # timeout por ejecución en segundos (30 min)
WORKDIR = os.getcwd()
RUNS_DIR = os.path.join(WORKDIR, "runs")
LOGS_DIR = os.path.join(WORKDIR, "logs")

# Rutas a tus scripts / wordlists (ajusta si están en otros paths)
PY_STREAM = os.path.join(WORKDIR, "bruteforce_get_stream.py")
PY_THREAD = os.path.join(WORKDIR, "bruteforce_get_threaded.py")
CURL_LOOP = os.path.join(WORKDIR, "curl_loop.sh")
# Hydra settings (ajusta chunk/wordlist)
HYDRA_CMD_TEMPLATE = ("hydra -s 8080 -t 32 -V -l admin -P rock_chunk_aa 127.0.0.1 http-get-form "
                      "'/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:"
                      "H=Cookie\\: security=low:Username and/or password incorrect'")

# Nombre de herramientas que vamos a comparar, en orden
TOOLS = ["hydra", "python_stream", "python_threaded", "curl_loop"]

# ---------- FIN CONFIG ----------

os.makedirs(RUNS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)


def which(cmd):
    return shutil.which(cmd) is not None


def run_cmd(cmd, cwd=None, timeout=TIMEOUT):
    """Ejecuta comando shell y devuelve (elapsed_seconds, stdout, stderr, returncode)."""
    start = time.perf_counter()
    try:
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              cwd=cwd, timeout=timeout, text=True)
        rc = proc.returncode
        out = proc.stdout
        err = proc.stderr
    except subprocess.TimeoutExpired as e:
        return (None, "", f"TIMEOUT after {timeout}s", -1)
    end = time.perf_counter()
    return (end - start, out, err, rc)


def run_tool_instance(tool, run_idx):
    """Ejecuta una instancia de tool y guarda salidas en runs/<tool>_<run_idx>/"""
    run_name = f"{tool}_{run_idx}"
    run_path = os.path.join(RUNS_DIR, run_name)
    os.makedirs(run_path, exist_ok=True)

    stdout_file = os.path.join(LOGS_DIR, f"{run_name}_stdout.txt")
    stderr_file = os.path.join(LOGS_DIR, f"{run_name}_stderr.txt")

    if tool == "hydra":
        if not which("hydra"):
            return {"ok": False, "note": "hydra_not_installed"}
        cmd = HYDRA_CMD_TEMPLATE + \
            f" | tee {os.path.join(run_path, 'hydra_output.txt')}"
    elif tool == "python_stream":
        if not os.path.exists(PY_STREAM):
            return {"ok": False, "note": f"missing {PY_STREAM}"}
        cmd = f"python3 {PY_STREAM} > {os.path.join(run_path, 'python_stream_stdout.txt')} 2> {os.path.join(run_path, 'python_stream_stderr.txt')}"
    elif tool == "python_threaded":
        if not os.path.exists(PY_THREAD):
            return {"ok": False, "note": f"missing {PY_THREAD}"}
        cmd = f"python3 {PY_THREAD} > {os.path.join(run_path, 'python_threaded_stdout.txt')} 2> {os.path.join(run_path, 'python_threaded_stderr.txt')}"
    elif tool == "curl_loop":
        if not os.path.exists(CURL_LOOP):
            return {"ok": False, "note": f"missing {CURL_LOOP}"}
        cmd = f"bash {CURL_LOOP} > {os.path.join(run_path, 'curl_loop_stdout.txt')} 2> {os.path.join(run_path, 'curl_loop_stderr.txt')}"
    else:
        return {"ok": False, "note": f"unknown_tool {tool}"}

    print(
        f"[RUNNING] {tool} (run {run_idx}) -> cmd: {cmd.splitlines()[0] if len(cmd.splitlines()) == 1 else cmd}")
    elapsed, out, err, rc = run_cmd(cmd, cwd=WORKDIR, timeout=TIMEOUT)
    # guardar stdout/stderr si run_cmd no via tee
    if out and "tee " not in cmd:
        open(os.path.join(run_path, f"{tool}_raw_stdout.txt"), "w").write(out)
    if err:
        open(os.path.join(run_path, f"{tool}_raw_stderr.txt"), "w").write(err)

    result = {"ok": True, "elapsed": elapsed, "rc": rc, "run_path": run_path}
    # intentar extraer métricas si los scripts generan archivos metrics_*.txt o results_*.txt
    # python_stream -> metrics_rockyou.txt (en cwd)
    metrics = {}
    # buscar archivos generados por el run en run_path o cwd
    # Common metric files expected:
    possible_metrics = ["metrics_rockyou.txt", "metrics.txt", "curl_metrics.txt",
                        "comparison_results.csv", "results.txt", "results_rockyou.txt"]
    for fname in possible_metrics:
        # chequea run_path y WORKDIR
        for check_dir in (run_path, WORKDIR):
            p = os.path.join(check_dir, fname)
            if os.path.exists(p):
                metrics[fname] = open(p).read()
    result["metrics"] = metrics
    return result


def aggregate_results(tool, timings):
    """Calcula mean/std/min/max de la lista timings (excluye None/timeouts)"""
    vals = [t for t in timings if (t is not None)]
    if not vals:
        return {"mean": None, "std": None, "min": None, "max": None, "runs": len(timings)}
    return {"mean": statistics.mean(vals), "std": statistics.stdev(vals) if len(vals) > 1 else 0.0,
            "min": min(vals), "max": max(vals), "runs": len(timings)}


def main():
    summary_rows = []
    overall_results = {}

    # decide que herramientas ejecutar: si hydra no esta, lo saltamos.
    tools_to_run = []
    for t in TOOLS:
        if t == "hydra" and not which("hydra"):
            print("[INFO] hydra no encontrado en PATH -> se omitirá en esta sesión")
            continue
        tools_to_run.append(t)

    print("[INFO] Herramientas a ejecutar:", tools_to_run)
    for tool in tools_to_run:
        timings = []
        notes = []
        for i in range(1, NUM_RUNS+1):
            print(f"\n--- Ejecutando {tool} (run {i}/{NUM_RUNS}) ---")
            res = run_tool_instance(tool, i)
            if not res.get("ok", False):
                print(
                    f"[WARN] {tool} run {i} no se ejecutó: {res.get('note')}")
                timings.append(None)
                notes.append(res.get("note"))
                continue
            # guardamos elapsed
            elapsed = res.get("elapsed")
            print(
                f"[DONE] {tool} run {i} elapsed={elapsed}s (rc={res.get('rc')})")
            timings.append(elapsed)
            # copiar cualquier metrics detectado dentro de run_path al logs para referencia
            for k, v in res.get("metrics", {}).items():
                ms_file = os.path.join(res["run_path"], f"detected_metric_{k}")
                open(ms_file, "w").write(v)
        agg = aggregate_results(tool, timings)
        overall_results[tool] = {
            "timings": timings, "agg": agg, "notes": notes}
        print(
            f"[SUMMARY] {tool}: mean={agg['mean']} std={agg['std']} min={agg['min']} max={agg['max']}\n")

    # escribir CSV resumen
    csv_file = os.path.join(WORKDIR, "comparison_new_results.csv")
    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["tool", "runs", "mean_time_s",
                        "std_s", "min_s", "max_s", "notes"])
        for tool, data in overall_results.items():
            a = data["agg"]
            notes = ";".join([n for n in data["notes"] if n])
            writer.writerow([tool, a["runs"], a["mean"] if a["mean"] is not None else "NA",
                             a["std"] if a["std"] is not None else "NA",
                             a["min"] if a["min"] is not None else "NA",
                             a["max"] if a["max"] is not None else "NA",
                             notes])
    print(f"[DONE] comparison CSV saved to {csv_file}")
    print("Runs and logs are under:", RUNS_DIR, LOGS_DIR)


if __name__ == "__main__":
    main()
