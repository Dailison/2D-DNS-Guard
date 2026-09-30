-- Botão Pausar do IA ao vivo (30/09, pedido do usuário): pausa de verdade a fila local (IA local: fases 1-3, listas e
-- investigação), a fila online (fase 4) ou o reforço (GPUs extras: a análise volta p/ a VM). Os workers leem a cada ~10 s.
CREATE TABLE IF NOT EXISTS controle (
    chave    text PRIMARY KEY,
    pausado  boolean NOT NULL DEFAULT false,
    por      text,
    em       timestamptz NOT NULL DEFAULT now()
);
INSERT INTO controle (chave) VALUES ('local'), ('online'), ('reforco') ON CONFLICT DO NOTHING;
