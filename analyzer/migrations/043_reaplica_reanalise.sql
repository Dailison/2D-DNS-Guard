-- As revisões pedidas (042) passaram pela fase 1 antes da correção da cascata: as que tinham ido p/ a IA online numa
-- rodada anterior (lista_duvida) ficaram na fila online sem passar pelas fases 2 e 3. Reaplica a resposta da IA local.
UPDATE domains SET lista_aplicada_at = NULL WHERE reanalise_pedida;
