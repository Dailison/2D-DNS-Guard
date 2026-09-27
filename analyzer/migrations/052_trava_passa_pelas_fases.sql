-- Pedido do usuário 27/09: nenhum domínio vai da fase 1 direto p/ a fase 4. Resposta da IA local com confiança alta
-- mas com trava (coerência, guardado, tirar da Infraestrutura, modelo sem autorização) também passa pelas fases 2
-- (WHOIS) e 3 (busca na web) antes da IA online — com mais evidência a trava pode sumir (ex.: SUSPEITO -> MALICIOSO).
ALTER TABLE domains ADD COLUMN IF NOT EXISTS lista_segue boolean NOT NULL DEFAULT false;

-- fila da fase 4 que pulou as fases 2/3 por trava: volta p/ a fase que falta
UPDATE domains d SET lista_duvida = false, lista_segue = true
WHERE d.kind = 'public' AND NOT d.llm_pending AND d.lista_fonte = 'local' AND d.lista_duvida
  AND (d.online_at IS NULL OR d.online_at < d.lista_at) AND d.lista_at >= d.analyzed_at
  AND (d.whois_at IS NULL OR d.web_search_at IS NULL);
