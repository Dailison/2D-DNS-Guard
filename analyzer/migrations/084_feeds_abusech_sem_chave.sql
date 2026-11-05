-- (05/11/2026) O abuse.ch tirou do ar os downloads sem chave (/downloads/hostfile/ responde 410 Gone desde
-- 21-22/10). URLhaus passa a vir do espelho malware-filter (mesmos hosts online do URLhaus, formato hosts,
-- atualizado a cada 12 h, sem chave). ThreatFox não tem espelho: fica na exportação com Auth-Key
-- (auth.abuse.ch); sem ABUSECH_AUTH_KEY no ambiente a fonte é pulada ("aguardando chave"), sem erro no log.
UPDATE ti_sources SET
    label = 'URLhaus (abuse.ch, via espelho malware-filter) — hosts online com malware',
    url = 'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt',
    refresh_hours = 6,
    license_note = 'URLhaus/abuse.ch (CC0) espelhado por malware-filter (CC0/MIT); o download direto do abuse.ch agora exige Auth-Key'
WHERE name = 'urlhaus' AND url = 'https://urlhaus.abuse.ch/downloads/hostfile/';

UPDATE ti_sources SET
    url = 'https://threatfox-api.abuse.ch/v2/files/exports/{ABUSECH_AUTH_KEY}/hostfile.txt',
    license_note = 'abuse.ch — exige Auth-Key (ABUSECH_AUTH_KEY; chave gratuita só para uso não comercial)'
WHERE name = 'threatfox' AND url = 'https://threatfox.abuse.ch/downloads/hostfile/';
