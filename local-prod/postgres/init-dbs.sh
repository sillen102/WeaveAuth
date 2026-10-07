#!/bin/sh
# One database and one login role per Ory service; runs once, on the first start of an empty volume.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<SQL
CREATE ROLE kratos LOGIN PASSWORD '$KRATOS_DB_PASSWORD';
CREATE DATABASE kratos OWNER kratos;
CREATE ROLE hydra LOGIN PASSWORD '$HYDRA_DB_PASSWORD';
CREATE DATABASE hydra OWNER hydra;
SQL
