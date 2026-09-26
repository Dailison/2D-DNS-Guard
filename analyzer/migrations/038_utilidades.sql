-- Categoria "Utilidades" (pedido do usuário 2026-09-26, ex.: convertio.co ia p/ Decisões): ferramentas online
-- legítimas — conversores de arquivo, PDF, tradutores, calculadoras. Vira também uma whitelist.
INSERT INTO site_categories (code, label, description, nonwork, sort_order) VALUES
 ('utilidades', 'Utilidades', 'Ferramentas online legítimas: conversores de arquivo, ferramentas de PDF, tradutores, calculadoras, encurtadores conhecidos', false, 12)
ON CONFLICT (code) DO NOTHING;

-- Decisões (fase 5) em que a IA online respondeu com pouca confiança: pergunta de novo (prompt melhor + segunda opinião).
UPDATE domains d SET online_at = NULL, lista_duvida = true
WHERE d.online_at IS NOT NULL AND coalesce((d.online_resp->>'confianca')::float, 0) < 0.8
  AND EXISTS (SELECT 1 FROM category_lists l WHERE l.category = 'para_revisar' AND l.domain = d.name);
