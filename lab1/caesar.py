#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
caesar.py — Cifrado/descifrado César simple con CLI.
Uso:
  python3 caesar.py --encrypt --shift 3 --text "hola mundo"
  python3 caesar.py --decrypt --shift 3 --text "krod pxqgr"
  echo "hola mundo" | python3 caesar.py --encrypt --shift 3
Notas:
- Solo desplaza letras [A-Z][a-z]; deja otros caracteres intactos (espacios, tildes, números, etc.).
"""
import sys
import argparse
from typing import Iterable

ALPH_LOW = "abcdefghijklmnopqrstuvwxyz"
ALPH_UP = ALPH_LOW.upper()

def caesar_char(ch: str, k: int) -> str:
    if ch in ALPH_LOW:
        return ALPH_LOW[(ALPH_LOW.index(ch) + k) % 26]
    if ch in ALPH_UP:
        return ALPH_UP[(ALPH_UP.index(ch) + k) % 26]
    return ch

def caesar(text: str, k: int, mode: str = "encrypt") -> str:
    k = k % 26
    if mode == "decrypt":
        k = (-k) % 26
    return "".join(caesar_char(c, k) for c in text)

def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(description="Cifrado César (encrypt/decrypt).")
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--encrypt", action="store_true", help="Cifrar texto")
    g.add_argument("--decrypt", action="store_true", help="Descifrar texto")
    parser.add_argument("--shift", "-k", type=int, required=True, help="Corrimiento (0..25)")
    parser.add_argument("--text", "-t", type=str, help="Texto de entrada. Si se omite, se lee de stdin.")
    args = parser.parse_args(list(argv))
    text = args.text if args.text is not None else sys.stdin.read()
    mode = "encrypt" if args.encrypt else "decrypt"
    out = caesar(text, args.shift, mode=mode)
    sys.stdout.write(out)
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
