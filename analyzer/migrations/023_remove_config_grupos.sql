-- Grupos de bloqueio foram substituídos pelas listas por categoria + políticas por empresa
-- (migrações 018-022). A config "grupo específico" do console não é mais usada.
DROP TABLE IF EXISTS group_settings;
