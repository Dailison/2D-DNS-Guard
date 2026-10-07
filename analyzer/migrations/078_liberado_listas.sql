-- IP liberado só em algumas listas (07/10, pedido do usuário): antes todo IP liberado ficava isento de TUDO (grupo
-- sem bloqueio no Technitium, inclusive ameaças). NULL = isento de tudo (como era); com listas = o IP segue a política
-- da rede dele, menos estas listas de bloqueio (o console monta o grupo no Technitium).
ALTER TABLE liberado_meta ADD COLUMN IF NOT EXISTS listas text[];
