-- Respostas "nenhuma lista" da IA online dadas antes das melhorias (busca na web, domínio técnico ->
-- lista do serviço, segunda opinião): ex. maoercdn.com (Maoer FM = streaming), manuscdn.com (Manus = IA),
-- telesco.pe (Telegram = mensageiros). Pergunta de novo (com segunda opinião obrigatória).
UPDATE domains SET online_at = NULL, lista_duvida = true
WHERE online_at < '2026-09-26 19:03:00-03' AND online_resp->>'lista' = 'nenhuma' AND NOT (online_resp ? 'erro');
