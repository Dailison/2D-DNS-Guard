-- WHOIS que falha sempre p/ um domínio (ex.: RDAP do TLD fora do ar) não pode travar a fase 3,
-- que agora espera o WHOIS: conta as tentativas; na 3ª falha desiste e segue.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS whois_tries smallint NOT NULL DEFAULT 0;
