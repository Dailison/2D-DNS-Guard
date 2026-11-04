#!/usr/bin/env python3
"""Clientes do WireGuard da 2D (wg0), como a tela de peers da Mikrotik: nome, IPs, endpoint, último handshake e
tráfego. Nome vem do comentário "# site N — Nome" em /etc/wireguard/wg0.conf (gravado pelo wg-site).
   wg-status            tabela
   wg-status -w 5       atualiza a cada 5 s (Ctrl+C sai)"""
import re
import subprocess
import sys
import time

CONF = "/etc/wireguard/wg0.conf"


def nomes():
    out, atual = {}, None
    for linha in open(CONF, encoding="utf-8"):
        m = re.match(r"#\s*site\s+(\d+)\s+[—-]\s*(.*)", linha.strip())
        if m:
            atual = (m.group(1), m.group(2).strip())
        m = re.match(r"PublicKey\s*=\s*(\S+)", linha.strip())
        if m and atual:
            out[m.group(1)] = atual
            atual = None
    return out


def humano_bytes(n):
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or u == "TiB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def humano_tempo(seg):
    if seg is None:
        return "nunca"
    if seg < 60:
        return f"{seg}s"
    if seg < 3600:
        return f"{seg // 60}m{seg % 60:02d}s"
    if seg < 86400:
        return f"{seg // 3600}h{seg % 3600 // 60:02d}m"
    return f"{seg // 86400}d{seg % 86400 // 3600}h"


def tabela():
    dump = subprocess.run(["wg", "show", "wg0", "dump"], capture_output=True, text=True, check=True).stdout.splitlines()
    nm, agora, linhas = nomes(), int(time.time()), []
    for l in dump[1:]:   # 1ª linha = a própria interface
        chave, _psk, endpoint, allowed, hs, rx, tx, _ka = l.split("\t")
        site, nome = nm.get(chave, ("?", "(sem nome no wg0.conf)"))
        hs = int(hs)
        idade = agora - hs if hs else None
        status = "ATIVO" if idade is not None and idade < 180 else ("FORA" if idade is not None else "NUNCA")
        ips = allowed.split(",")
        linhas.append((int(site) if site.isdigit() else 999, site, nome, ips[0], ",".join(ips[1:]) or "-",
                       endpoint if endpoint != "(none)" else "-", humano_tempo(idade), humano_bytes(int(rx)),
                       humano_bytes(int(tx)), status))
    linhas.sort()
    cab = ("SITE", "NOME", "TÚNEL", "REDES", "ENDPOINT", "HANDSHAKE", "RX", "TX", "STATUS")
    dados = [x[1:] for x in linhas]
    larg = [max(len(str(c)) for c in col) for col in zip(cab, *dados)] if dados else [len(c) for c in cab]
    fmt = "  ".join(f"{{:<{w}}}" for w in larg)
    print(fmt.format(*cab))
    for d in dados:
        print(fmt.format(*d))
    ativos = sum(1 for d in dados if d[-1] == "ATIVO")
    print(f"\n{ativos} de {len(dados)} clientes ativos (handshake nos últimos 3 min) — {time.strftime('%d/%m %H:%M:%S')}")


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] in ("-w", "--watch"):
        intervalo = int(sys.argv[2]) if len(sys.argv) > 2 else 5
        try:
            while True:
                print("\033[2J\033[H", end="")
                tabela()
                time.sleep(intervalo)
        except KeyboardInterrupt:
            pass
    else:
        tabela()
