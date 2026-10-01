-- Cota diária das fontes externas gratuitas, gravada (01/10): o limite do VirusTotal (500/dia) ficava só na memória e
-- zerava a cada reinício — a investigação gastou os 500 e a verificação da infraestrutura (antes da whitelist) ficou
-- parada. Agora cada uso tem a sua parte do dia (investigação / verificação) e a conta sobrevive a reinícios.
CREATE TABLE IF NOT EXISTS fonte_cota (
    fonte  text NOT NULL,          -- ex.: virustotal:investigacao, virustotal:verificacao
    dia    date NOT NULL,          -- dia UTC (é quando o VirusTotal zera)
    n      int  NOT NULL DEFAULT 0,
    PRIMARY KEY (fonte, dia)
);
