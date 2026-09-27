-- Prova de 27/09 (50 domínios: fases 1-3 da IA local x IA online): a IA local não acertou 100% no bloqueio, então pôr
-- numa lista / tirar de uma volta a ter a validação da IA online. O que ela aplicou sozinha entre 00:03 e agora
-- (20 inclusões, 7 remoções — ex.: vr.com.br e statusinvest.com.br em Compras) vai p/ a IA online revalidar.
UPDATE domains d SET lista_duvida = true
WHERE d.name IN (SELECT domain FROM list_audit WHERE at > '2026-09-27 00:03:50-03' AND motivo LIKE 'IA local%');
