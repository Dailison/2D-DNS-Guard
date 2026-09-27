-- IA local nova (pedido do usuário 27/09): gemma4:26b no PC (GPU) e na VM (reserva), decidindo sozinha com confiança
-- alta (LOCAL_DECIDE_MODELS); resposta de modelo que não passou na prova (qwen3:8b) sempre vai p/ a IA online.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS lista_modelo text;   -- modelo local que deu a resposta de lista em uso

-- backlog: o que espera a IA online e veio da IA local antiga (qwen3:8b) volta p/ a fase 1 com o modelo novo
UPDATE domains d SET llm_pending = true, lista_duvida = false, reanalise_pedida = dominio_decidido(d.id), claimed_at = NULL
WHERE d.kind = 'public' AND d.lista_duvida AND d.lista_fonte = 'local' AND (d.online_at IS NULL OR d.online_at < d.lista_at);
