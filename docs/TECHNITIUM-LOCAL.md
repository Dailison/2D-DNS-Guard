# Technitium local (10.100.10.15)

VM `2dadguard001` (Debian 13, ~880 MB de RAM, disco de 57 GB). É o resolvedor/filtro do escritório e a 2ª opção de DNS
dos clientes (a 1ª é o Technitium Cloud, `10.250.100.1`, na VPS), menos nos 21 sites na Gigabyte, onde ele é a 1ª opção
(ver [MIGRACAO-HUB-VPS.md](MIGRACAO-HUB-VPS.md#sites-na-gigabyte-local-na-frente-06112026)).

| Item | Onde |
|---|---|
| Acesso | `ssh -i ~/.ssh/id_ed25519 root@10.100.10.15` (PC do escritório) |
| Console | `http://10.100.10.15:5380/` |
| Serviço | systemd `dns` (usuário `dns-server`), runtime .NET em `/opt/dotnet` |
| Programa | `/opt/technitium/dns` |
| Configuração | `/etc/dns` (apps Advanced Blocking e Query Logs Sqlite; os logs de consulta ocupam ~3 GB e as estatísticas ~1,8 GB) |
| Log do servidor | `/var/log/technitium/dns/<data>.log` |
| Certificado | `/etc/dns/cert.pfx` (ver [ops/technitium-cert-sync](../ops/technitium-cert-sync/README.md)) |

## Atualizar

O instalador oficial atualiza o runtime .NET 10 e o programa, ajusta as permissões e reinicia o serviço. A
configuração em `/etc/dns` não é tocada. O DNS fica fora ~16 s.

```
# versão instalada (o host não tem "strings")
python3 -c 'import re;b=open("/opt/technitium/dns/DnsServerCore.dll","rb").read();i=b.find("ProductVersion".encode("utf-16-le"));print(re.findall(r"[0-9]+\.[0-9]+(?:\.[0-9]+)*",b[i:i+80].decode("utf-16-le","ignore")))'
# backup antes
tar --exclude=/etc/dns/cache.bin -czf /root/backup-etc-dns-antes-<versao>-$(date +%Y%m%d-%H%M).tgz /etc/dns
cp -a /opt/technitium/dns /root/opt-technitium-dns-<versao-atual>
# instalador (revisar antes; é o mesmo para instalar e para atualizar)
curl -sSL https://download.technitium.com/dns/install.sh -o /root/install.sh && sh /root/install.sh
```

Conferir depois: `systemctl is-active dns`, a linha `DNS Server (vX) was started successfully` no log do dia, o
Advanced Blocking relendo as listas de `http://10.100.50.202:8088/listas/` e uma consulta (`nslookup google.com
10.100.10.15`).

Durante o reinício, os sites de outros provedores não sentem (usam o Cloud). Os 21 sites na Gigabyte e o escritório
usam o local primeiro: trocam sozinhos para o Cloud se a queda passar de ~15 s. Failover do escritório em [MIGRACAO-HUB-VPS.md](MIGRACAO-HUB-VPS.md#escritório-2drtr001-failover-com-o-local-na-frente-06112026).

## Histórico

| Data | O quê |
|---|---|
| 06/11/2026 | 15.6 → **15.6.2**; .NET 10.0.12 → 10.0.14. Backups em `/root`: `backup-etc-dns-antes-15.6.2-20261106-1924.tgz` (1,4 GB, pode apagar depois de uns dias) e `opt-technitium-dns-15.6`. |
