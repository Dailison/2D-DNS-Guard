#!/usr/bin/env python3
"""Gera a configuração do BGP da 2D a partir de docs/scripts/bgp-sites.txt (tabela única).

  bgp-gera.py frr                 -> /etc/frr/frr.conf da VPS (todos os sites da tabela)
  bgp-gera.py escritorio-prep     -> 2DRTR001: chain bgp-in-vps por site (+ "rejeita o resto")
  bgp-gera.py escritorio N        -> 2DRTR001: peer antigo ativo, filtros e sessão direta com o site N
  bgp-gera.py site N              -> roteador do site N (instância, filtros, sessões, nota, reversão em 10 min)
  bgp-gera.py confirma N          -> roteador do site N: cancela a reversão automática
  bgp-gera.py nota-escritorio     -> 2DRTR001: /system note

Modelo (testado em 05/11/2026, ver docs/BGP-TESTE.md e docs/BGP-PRODUCAO.md):
  VPS AS65250 (não instala rotas), escritório AS65100, site N = AS(65000+N), router-id 10.250.100.N.
  Escritório <-> site: túnel antigo direto (local-pref 150, principal) e VPS (100, reserva).
  Par: pela VPS (100) ou por túnel direto próprio (200). Cada um anuncia só as próprias redes.
"""
import os
import re
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
TABELA = os.path.join(AQUI, "bgp-sites.txt")
DATA = "05/11/2026"
DOC = "docs/BGP-PRODUCAO.md (repositorio 2D-DNS-Guard)"


def carrega():
    sites = {}
    for linha in open(TABELA, encoding="utf-8"):
        linha = linha.strip()
        if not linha or linha.startswith("#"):
            continue
        c = [x.strip() for x in linha.split("|")]
        c += [""] * (6 - len(c))
        n = int(c[0])
        redes = [] if c[3] in ("", "-") else [r.strip() for r in c[3].split(",") if r.strip()]
        sites[n] = {
            "n": n, "nome": c[1], "ifantigo": c[2], "redes": redes,
            "extras": [r for r in redes if not r.startswith(f"10.{n}.")],
            "par": int(c[4]) if c[4] else None, "obs": c[5].split(),
        }
    return sites


def slug(nome):
    return re.sub(r"[^a-z0-9]", "", nome.lower())


def cond_site(s):
    """Condição RouterOS: as redes que o site N pode anunciar (a /16 + as extras exatas)."""
    partes = [f"dst in 10.{s['n']}.0.0/16"] + [f"dst in {e}" for e in s["extras"]]
    return " || ".join(partes)


def frr(sites):
    o = []
    o.append("! BGP da 2D. A VPS é hub: decide o que cada site recebe e NÃO instala rotas")
    o.append("! (o encaminhamento segue pelos AllowedIPs do wg0). GERADO por docs/scripts/bgp-gera.py a partir de")
    o.append("! docs/scripts/bgp-sites.txt (2D-DNS-Guard): não editar aqui. Ver docs/BGP-PRODUCAO.md.")
    o += ["frr defaults traditional", "hostname srv2124756.hstgr.cloud", "log syslog informational", "!",
          "route-map NAO-INSTALA deny 10", "ip protocol bgp route-map NAO-INSTALA", "!",
          "ip prefix-list ESCRITORIO seq 5 permit 10.100.0.0/16 ge 16 le 24"]
    for n, s in sorted(sites.items()):
        o.append(f"ip prefix-list SITE{n} seq 5 permit 10.{n}.0.0/16 ge 16 le 24")
        for i, e in enumerate(s["extras"]):
            o.append(f"ip prefix-list SITE{n} seq {10 + 5 * i} permit {e}")
    o += ["!", "! o que cada vizinho pode anunciar (só as próprias redes)",
          "route-map DE-ESCRITORIO permit 10", " match ip address prefix-list ESCRITORIO"]
    for n in sorted(sites):
        o += [f"route-map DE-SITE{n} permit 10", f" match ip address prefix-list SITE{n}"]
    o += ["!", "! o que cada vizinho recebe: escritório = todos os sites; site = escritório (+ o par)"]
    for i, n in enumerate(sorted(sites)):
        o += [f"route-map PARA-ESCRITORIO permit {10 * (i + 1)}", f" match ip address prefix-list SITE{n}"]
    for n, s in sorted(sites.items()):
        o += [f"route-map PARA-SITE{n} permit 10", " match ip address prefix-list ESCRITORIO"]
        if s["par"]:
            o += [f"route-map PARA-SITE{n} permit 20", f" match ip address prefix-list SITE{s['par']}"]
    o += ["!", "router bgp 65250", " bgp router-id 10.250.100.1", " bgp log-neighbor-changes"]
    viz = [("10.250.100.100", 65100, "escritorio 2DRTR001")] + \
          [(f"10.250.100.{n}", 65000 + n, s["nome"]) for n, s in sorted(sites.items())]
    for ip, asn, desc in viz:
        o += [f" neighbor {ip} remote-as {asn}", f" neighbor {ip} description {desc}",
              f" neighbor {ip} timers 3 9", f" neighbor {ip} timers connect 5"]
    o.append(" address-family ipv4 unicast")
    for ip, asn, desc in viz:
        nome = "ESCRITORIO" if asn == 65100 else f"SITE{asn - 65000}"
        o += [f"  neighbor {ip} next-hop-self", f"  neighbor {ip} route-map DE-{nome} in",
              f"  neighbor {ip} route-map PARA-{nome} out"]
    o += [" exit-address-family", "!"]
    return "\n".join(o) + "\n"


def escritorio_prep(sites):
    o = ["# 2DRTR001: chain bgp-in-vps com uma regra por site (+ rejeita o resto)",
         '/routing filter rule remove [find chain=bgp-in-vps]']
    for n, s in sorted(sites.items()):
        if "feito" in s["obs"]:
            o.append(regra_vps_escritorio(s, place=False))
    o.append('/routing filter rule add chain=bgp-in-vps comment="bgp-2d: da VPS rejeita o resto (cada site tem a sua regra acima)" rule="reject"')
    return "\n".join(o) + "\n"


def regra_vps_escritorio(s, place=True):
    r = (f'/routing filter rule add chain=bgp-in-vps comment="bgp-2d: {s["nome"]} ({s["n"]}) pela VPS (reserva)" '
         f'rule="if (({cond_site(s)}) && dst-len <= 24) {{ accept }}"')
    if place:
        r += ' place-before=[find chain=bgp-in-vps and comment~"rejeita o resto"]'
    return r


def escritorio(s):
    n, nome = s["n"], s["nome"]
    o = [f"# 2DRTR001: BGP com {nome} ({n})",
         # peer antigo ativo e marcado: é o caminho principal
         f':foreach p in=[/interface wireguard peers find where interface=wireguard_2D] do={{ '
         f':if ([:typeof [:find [:tostr [/interface wireguard peers get $p allowed-address]] "10.100.100.{n}/32"]] != "nil") do={{ '
         f':local c [/interface wireguard peers get $p comment]; '
         f':if ([:typeof [:find $c "bgp-2d"]] = "nil") do={{ /interface wireguard peers set $p comment=($c . " | bgp-2d: tunel direto = caminho principal (nao desativar)") }}; '
         f'/interface wireguard peers set $p disabled=no; '
         # rede extra fora do allowed-address do peer antigo: o WireGuard descartaria o caminho direto
         + "".join(f':if ([:typeof [:find [:tostr [/interface wireguard peers get $p allowed-address]] "{e}"]] = "nil") do={{ '
                   f'/interface wireguard peers set $p allowed-address=([/interface wireguard peers get $p allowed-address], {e}) }}; '
                   for e in s["extras"])
         + '} }',
         f'/routing filter rule add chain=bgp-in-{n} comment="bgp-2d: {nome} direto (PRINCIPAL para escritorio<->site)" '
         f'rule="if (({cond_site(s)}) && dst-len <= 24) {{ set bgp-local-pref 150; accept }} else {{ reject }}"',
         regra_vps_escritorio(s),
         f'/routing bgp connection add name=bgp-{slug(nome)} comment="bgp-2d: {nome} direto" instance=bgp-2d '
         f'remote.address=10.100.100.{n} remote.as={65000 + n} local.address=10.100.100.1 local.role=ebgp '
         f'hold-time=9s keepalive-time=3s input.filter=bgp-in-{n} output.filter-chain=bgp-out output.network=BGP_REDES']
    for e in s["extras"]:
        # a estática da rede extra (distance=1) ganharia do BGP (20): vira reserva
        o.append(f'/ip route set [find dst-address={e} and comment~"hub novo"] distance=30')
    return "\n".join(o) + "\n"


def nota_site(s, sites):
    n = s["n"]
    par = ""
    if s["par"]:
        p = sites[s["par"]]
        via = ("tunel direto proprio wg-par-* (BGP bgp-par-*, local-pref 200, principal); VPS = reserva"
               if "par-direto" in s["obs"] else "pela VPS (o par so conversa com o par)")
        par = f"\\n - par {p['nome']} ({p['n']}, 10.{p['n']}.0.0/16): {via}"
    return (f"2D Tecnologia - roteamento dinamico BGP (desde {DATA})\\n"
            f"Site {n} {s['nome']}: AS{65000 + n}, router-id 10.250.100.{n}.\\n"
            f"Caminhos ate o escritorio da 2D (10.100.0.0/16):\\n"
            f" - principal: tunel antigo {s['ifantigo']} (vizinho 10.100.100.1, AS65100, local-pref 150)\\n"
            f" - reserva: tunel novo wg-vps-2d (vizinho VPS 10.250.100.1, AS65250); troca sozinha em ~10 s{par}\\n"
            f"Anuncia so as proprias redes (address-list BGP_REDES). Recebe so o escritorio (e o par).\\n"
            f"As rotas estaticas 'hub novo' (/16 pela VPS) ficam como rede de seguranca.\\n"
            f"Tudo do BGP tem comentario bgp-2d. NAO desativar o peer do tunel antigo: e o caminho principal.\\n"
            f"Para incluir/remover rede: address-list BGP_REDES aqui E a tabela docs/scripts/bgp-sites.txt.\\n"
            f"Desfazer: remover tudo com comentario bgp-2d (bgp connection, bgp instance, filter rule, address-list, nat).\\n"
            f"Documentacao: {DOC}")


def site(s, sites):
    n, nome, ifa = s["n"], s["nome"], s["ifantigo"]
    c_esc = "dst in 10.100.0.0/16"
    c_vps = c_esc
    if s["par"]:
        c_vps = f"{c_esc} || {cond_site(sites[s['par']])}"
    o = [f"# {nome} ({n}): BGP com o escritorio (direto) e a VPS"]
    if "sem-scheduler" not in s["obs"]:
        o.append('/system scheduler add name=rollback-bgp interval=10m comment="bgp-2d: reversao automatica (cancelar depois de conferir)" '
                 'on-event="/routing bgp connection remove [find comment~\\"bgp-2d\\"]; /routing bgp instance remove [find comment~\\"bgp-2d\\"]; '
                 '/routing filter rule remove [find comment~\\"bgp-2d\\"]; /ip firewall address-list remove [find comment~\\"bgp-2d\\"]; '
                 '/ip firewall nat remove [find comment~\\"bgp-2d\\"]; /system scheduler remove [find name=rollback-bgp]"')
    o.append(f'/routing bgp instance add name=bgp-2d as={65000 + n} router-id=10.250.100.{n} comment="bgp-2d: AS do site {n} {nome}"')
    for r in s["redes"]:
        o.append(f'/ip firewall address-list add list=BGP_REDES address={r} comment="bgp-2d: redes do site (anunciadas)"')
    o += [f'/routing filter rule add chain=bgp-out comment="bgp-2d: site anuncia so as proprias redes" rule="if ({cond_site(s)}) {{ accept }} else {{ reject }}"',
          f'/routing filter rule add chain=bgp-in-vps comment="bgp-2d: da VPS: escritorio{" + par" if s["par"] else ""} (reserva)" rule="if (({c_vps}) && dst-len <= 24) {{ accept }} else {{ reject }}"',
          f'/routing filter rule add chain=bgp-in-direto comment="bgp-2d: escritorio direto (PRINCIPAL; VPS = reserva)" rule="if ({c_esc} && dst-len <= 24) {{ set bgp-local-pref 150; accept }} else {{ reject }}"',
          # sem NAT para o túnel antigo (há masquerade sem interface de saída em alguns sites)
          f':if ([:len [/ip firewall nat find where chain=srcnat and out-interface="{ifa}" and action=accept]] = 0) do={{ '
          f':local f [/ip firewall nat find]; :if ([:len $f] > 0) do={{ /ip firewall nat add chain=srcnat action=accept out-interface="{ifa}" '
          f'comment="bgp-2d: sem NAT no tunel antigo (escritorio)" place-before=[:pick $f 0] }} else={{ /ip firewall nat add chain=srcnat '
          f'action=accept out-interface="{ifa}" comment="bgp-2d: sem NAT no tunel antigo (escritorio)" }} }}',
          f'/routing bgp connection add name=bgp-vps comment="bgp-2d: VPS (reserva)" instance=bgp-2d remote.address=10.250.100.1 remote.as=65250 '
          f'local.address=10.250.100.{n} local.role=ebgp hold-time=9s keepalive-time=3s input.filter=bgp-in-vps output.filter-chain=bgp-out output.network=BGP_REDES',
          f'/routing bgp connection add name=bgp-escritorio comment="bgp-2d: escritorio direto pelo {ifa} (principal)" instance=bgp-2d '
          f'remote.address=10.100.100.1 remote.as=65100 local.address=10.100.100.{n} local.role=ebgp hold-time=9s keepalive-time=3s '
          f'input.filter=bgp-in-direto output.filter-chain=bgp-out output.network=BGP_REDES',
          f'/system note set show-at-login=no note="{nota_site(s, sites)}"']
    return "\n".join(o) + "\n"


def nota_escritorio(sites):
    return ('/system note set show-at-login=no note="2D Tecnologia - roteamento dinamico BGP (desde ' + DATA + ')\\n'
            '2DRTR001: AS65100, router-id 10.100.30.1. Anuncia so 10.100.0.0/16 (address-list BGP_REDES).\\n'
            'Cada site N (AS 65000+N) tem duas sessoes: direta pelo wireguard_2D (bgp-<nome>, filtro bgp-in-N,\\n'
            'local-pref 150 = principal) e pela VPS 10.250.100.1 (bgp-vps, AS65250, filtro bgp-in-vps = reserva).\\n'
            'NAO desativar os peers do wireguard_2D marcados com bgp-2d: sao o caminho principal.\\n'
            'Rotas estaticas hub novo (/16 pela VPS) ficam como rede de seguranca; extras 192.168/172.16 com distance=30.\\n'
            'Mudou rede/site: tabela docs/scripts/bgp-sites.txt e gerador docs/scripts/bgp-gera.py.\\n'
            'Documentacao: ' + DOC + '"\n')


def main():
    # no Windows a saída padrão seria cp1252 + CRLF: o FRR e o RouterOS querem UTF-8 + LF
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    sites = carrega()
    a = sys.argv[1:]
    if not a:
        sys.exit(__doc__)
    if a[0] == "frr":
        sys.stdout.write(frr(sites))
    elif a[0] == "escritorio-prep":
        sys.stdout.write(escritorio_prep(sites))
    elif a[0] == "escritorio":
        sys.stdout.write(escritorio(sites[int(a[1])]))
    elif a[0] == "site":
        sys.stdout.write(site(sites[int(a[1])], sites))
    elif a[0] == "confirma":
        sys.stdout.write("/system scheduler remove [find name=rollback-bgp]\n")
    elif a[0] == "nota-escritorio":
        sys.stdout.write(nota_escritorio(sites))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
