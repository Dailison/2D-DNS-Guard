-- Console web do 2D DNS Guard (dns-guard.2dtecnologia.com): operadores e metadados
-- dos IPs liberados. A isenção em si vive no Technitium (networkGroupMap); aqui só
-- a descrição (empresa/departamento/usuário/tipo). Migrados do MySQL do HotspotPortal.
CREATE TABLE IF NOT EXISTS console_operators (
    id         serial PRIMARY KEY,
    email      text NOT NULL UNIQUE,
    nome       text NOT NULL,
    senha_hash text,                         -- werkzeug; NULL = só login único (2D Hub)
    is_super   boolean NOT NULL DEFAULT false,
    ativo      boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_login timestamptz
);

CREATE TABLE IF NOT EXISTS liberado_meta (
    ip           text PRIMARY KEY,           -- normalizado, ex.: 10.100.10.20/32
    empresa      text,
    departamento text,
    usuario      text,
    tipo         text,                       -- Computador | Celular
    created_at   timestamptz NOT NULL DEFAULT now(),
    created_by   text
);
