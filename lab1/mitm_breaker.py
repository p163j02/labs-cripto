#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mitm_breaker.py — MitM pasivo: reconstruye el mensaje completo (incluye sentinela)
y prueba todos los corrimientos César para descifrar.
"""
import sys, argparse
from typing import List
from scapy.all import sniff, Raw, ICMP  # type: ignore

INJECT_OFFSET = 0x0F

def score_spanish(text: str) -> float:
    text_low = text.lower()
    score = 0.0
    # Palabras claras -> alto peso
    strong_words = ["mensaje", "secreto", "criptografia", "seguridad", "redes"]
    for w in strong_words:
        if w in text_low:
            score += 100
    # Palabras comunes -> peso moderado
    common_words = [" el ", " la ", " de ", " que ", " y ", " en ", " se ", 
                    " por ", " con ", " un ", " para ", " es ", " al ", " como "]
    for w in common_words:
        score += text_low.count(w) * 3.0
    vowels = sum(text_low.count(v) for v in "aeiouáéíóú")
    score += vowels * 0.5
    bad_chars = sum(1 for ch in text_low if ch not in "abcdefghijklmnopqrstuvwxyzáéíóúñ ")
    score -= bad_chars * 2.0
    return score

def caesar(text: str, k: int) -> str:
    def shift(ch):
        if 'a' <= ch <= 'z':
            return chr((ord(ch) - 97 - k) % 26 + 97)
        if 'A' <= ch <= 'Z':
            return chr((ord(ch) - 65 - k) % 26 + 65)
        return ch
    return "".join(shift(c) for c in text)

def sniff_message(bpf_filter: str, max_packets: int) -> str:
    print(f"[i] Sniffing con filtro: {bpf_filter!r}")
    msg_chars: List[str] = []
    for p in sniff(filter=bpf_filter, count=max_packets):
        if ICMP in p and p[ICMP].type == 8 and Raw in p:
            data = bytes(p[ICMP].payload.load)
            if len(data) > INJECT_OFFSET:
                ch = chr(data[INJECT_OFFSET])
                msg_chars.append(ch)
                print(f"  - visto char '{ch}' (0x{data[INJECT_OFFSET]:02x}); len={len(msg_chars)}")
    return "".join(msg_chars)

def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Reconstruye mensaje completo (incluye sentinela) y prueba corrimientos César.")
    parser.add_argument("--filter", default="icmp", help="Filtro BPF (Wireshark/tcpdump style)")
    parser.add_argument("--max", type=int, default=500, help="Máximo paquetes a olfatear")
    args = parser.parse_args(argv)

    captured = sniff_message(args.filter, args.max)
    if not captured:
        print("[!] No se capturó mensaje (¿filtro correcto? ¿offset correcto?).")
        return 1

    print(f"[✓] Mensaje capturado (cifrado, incluye sentinela): {captured!r}\n")

    # Descifrar ignorando SOLO el último carácter (sentinela)
    real_cipher = captured[:-1]

    print("[i] Candidatos (k=0..25):")
    best_k, best_text, best_score = 0, "", float("-inf")
    for k in range(26):
        cand = caesar(real_cipher, k)
        s = score_spanish(cand)
        if s > best_score:
            best_k, best_text, best_score = k, cand, s
        print(f"k={k:02d} -> {cand}")
    print("\n\033[92m[✓] Opción más probable: k=%d -> %s\033[0m" % (best_k, best_text))
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

