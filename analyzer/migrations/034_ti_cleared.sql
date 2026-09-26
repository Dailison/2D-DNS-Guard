-- Plano de confiabilidade, fase 4.1: quando o domínio sai dos feeds de ameaça (ti_signature fica vazio),
-- guarda quando saiu — o bloqueio automático em Ameaças expira depois de alguns dias fora dos feeds.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS ti_cleared_at timestamptz;
