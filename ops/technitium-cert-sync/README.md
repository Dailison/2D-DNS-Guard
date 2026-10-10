# Certificado do Technitium (DoT, DoH e console)

O Technitium (`10.100.10.15`, `/etc/dns/cert.pfx`, sem senha) usa o certificado `2dtecnologia.com`, emitido e renovado
pelo cert-manager no k3s (secret `2d-sites/2dtecnologia-tls`). Ele não renova sozinho: até 10/10/2026 o arquivo era
copiado à mão.

- `technitium-cert-sync.sh` — roda no nó do k3s, usuário `claude`, pelo cron (`40 4 * * *`, cópia em `~/bin`, saída em
  `~/technitium-cert-sync.log`). Lê o secret, monta o PFX e o envia por SSH.
- `technitium-instalar-cert` — fica em `/usr/local/sbin/` no servidor do Technitium. É o comando forçado da chave
  `technitium-cert-sync@2d-server` no `authorized_keys` do root: essa chave não abre shell, só entrega um PFX. O
  instalador recusa o que não for um PFX válido, com chave, do nome esperado e com validade maior que a do instalado;
  guarda o anterior em `cert.pfx.anterior`.

O Technitium recarrega o arquivo sozinho em até um minuto (sem reiniciar). Conferir o que está sendo servido:

    echo | openssl s_client -connect 10.100.10.15:853 -servername 2dtecnologia.com 2>/dev/null | openssl x509 -noout -enddate
