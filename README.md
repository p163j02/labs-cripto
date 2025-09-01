# Laboratorio 1 - Criptografía y Canales Encubiertos ICMP

Este repositorio contiene los scripts desarrollados para el laboratorio de criptografía:

1. **Cifrado César** (`caesar.py`)
2. **Stealth Ping** (`stealth_ping.py`)
3. **Man-in-the-Middle Breaker** (`mitm_breaker.py`)

---

## 1. Cifrado César (`caesar.py`)

### Descripción

Implementa el cifrado y descifrado de texto mediante el algoritmo César, con un desplazamiento (`--shift`) configurable.

### Uso

```bash
python3 caesar.py --encrypt --shift 9 --text "mensaje secreto"
python3 caesar.py --decrypt --shift 9 --text "vfwbcrn bljxbcn"
```

---

## 2. Stealth Ping (`stealth_ping.py`)

### Descripción

Inyecta mensajes cifrados en paquetes ICMP sin alterar campos críticos, utilizando un ping real como plantilla.

### Requisitos

- **Permisos root** para enviar paquetes raw.
- Un ping real al destino para generar la plantilla.

### Uso

En una terminal, envía un ping real:

```bash
ping -c 1 8.8.8.8
```

En otra terminal, ejecuta el script:

```bash
sudo python3 stealth_ping.py --dst 8.8.8.8     --message "mensaje_cifrado" --shift 9
```

**Nota:**

- El mensaje se cifra con César y se envía byte a byte.
- El script añade un marcador final `'b'` para indicar fin de mensaje.

---

## 3. MitM Breaker (`mitm_breaker.py`)

### Descripción

Captura tráfico ICMP stealth, reconstruye el mensaje cifrado y aplica fuerza bruta sobre el cifrado César para recuperar el texto original.

### Uso

```bash
sudo python3 mitm_breaker.py --filter "icmp and host 8.8.8.8" --max 200
```

### Salida esperada

- Muestra el mensaje capturado en crudo (`\x00...`).
- Lista candidatos k=0..25 y señala la opción más probable.
- El mensaje real se identifica fácilmente observando el candidato correcto.

---

## Flujo del Laboratorio

1. **Actividad 1:** Cifrar el mensaje con `caesar.py`.
2. **Actividad 2:** Inyectar el mensaje cifrado usando `stealth_ping.py` y capturar evidencia con Wireshark.
3. **Actividad 3:** Interceptar el tráfico con `mitm_breaker.py` y descifrar el mensaje completo.

## Ejemplo de flujo de ejecución

1. Cifrar mensaje:

```bash
python3 caesar.py --encrypt --shift 9 --text "criptografia y seguridad en redes"
```

2. Enviar por ICMP stealth:

```bash
ping -c 1 8.8.8.8   # ping real (otra terminal)
sudo python3 stealth_ping.py --dst 8.8.8.8     --message "mensaje_cifrado" --shift 9
```

3. Interceptar y descifrar:

```bash
sudo python3 mitm_breaker.py --filter "icmp and host 8.8.8.8" --max 200
```

---

## Autor

- **Felipe Farfán Alvarado**
- Universidad Diego Portales - Criptografía y seguridad en redes (2025)
