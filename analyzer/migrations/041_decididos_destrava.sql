-- Domínio decidido não passa pela fase 1 (IA local), mas um reprocessamento em lote marcou 81 deles com
-- llm_pending = true (quase todos sites adultos já bloqueados, como DESCONHECIDO) e a fila online exigia
-- NOT llm_pending: ficavam presos. A fila agora ignora llm_pending de decidido; aqui limpa a marca.
UPDATE domains SET llm_pending = false WHERE llm_pending AND dominio_decidido(id);
