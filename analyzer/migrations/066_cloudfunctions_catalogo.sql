-- cloudfunctions.net (Google Cloud Functions) passou a ser do catálogo, como amazonaws.com e cloudfront.net (29/09):
-- sem IA, whitelist Infraestrutura. Os que já foram vistos voltam às regras (que agora os classificam pelo catálogo) e
-- a pergunta de lista grava a whitelist sem chamar a IA. Ficam como estão: travados à mão e quem está numa lista de
-- bloqueio (jogo, ameaça… identificados pela IA ou por pessoa — o catálogo não desbloqueia).
UPDATE domains d SET needs_analysis = true
WHERE d.kind = 'public' AND NOT d.locked AND (d.name = 'cloudfunctions.net' OR d.name LIKE '%.cloudfunctions.net')
  AND NOT EXISTS (SELECT 1 FROM category_lists l WHERE l.domain = d.name AND l.category NOT IN ('para_revisar', 'nao_identificado'));
