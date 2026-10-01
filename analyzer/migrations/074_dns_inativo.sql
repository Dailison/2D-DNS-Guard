-- Lista de bloqueio "DNS Inativo" (01/10, pedido do usuário): domínio que não resolve (não devolve IP) vai p/ ela já na
-- etapa 1, sem IA (dnsativo.py). Vale onde "Não identificados" já vale (o console publica no Technitium ao sincronizar).
UPDATE policies SET lists = array_append(lists, 'dns_inativo'), updated_at = now()
WHERE 'nao_identificado' = ANY(lists) AND NOT ('dns_inativo' = ANY(lists));
