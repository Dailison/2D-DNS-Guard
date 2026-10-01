-- Investigação de novo para TODOS os desconhecidos (30/09, pedido do usuário: os métodos melhoraram — coleta ampla,
-- certificado, OTX, VirusTotal, URLScan…). A fila da fase 6 passa a aceitar também os já decididos (pela IA ou por
-- pessoa), menos os liberados (whitelist ou decisão "liberado") — investigacao.FILA_SQL. Aqui só zera a data da
-- última investigação p/ todos voltarem à fila.
UPDATE domains SET investigado_at = NULL
WHERE kind = 'public' AND classification = 'DESCONHECIDO' AND investigado_at IS NOT NULL;
