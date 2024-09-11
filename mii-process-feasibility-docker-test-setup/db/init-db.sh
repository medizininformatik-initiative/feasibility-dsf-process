#!/usr/bin/env bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE DATABASE zars_fhir;
    GRANT ALL PRIVILEGES ON DATABASE zars_fhir TO liquibase_user;
    CREATE DATABASE zars_bpe;
    GRANT ALL PRIVILEGES ON DATABASE zars_bpe TO liquibase_user;
    CREATE DATABASE dic_1_fhir;
    GRANT ALL PRIVILEGES ON DATABASE dic_1_fhir TO liquibase_user;
    CREATE DATABASE dic_1_bpe;
    GRANT ALL PRIVILEGES ON DATABASE dic_1_bpe TO liquibase_user;
    CREATE DATABASE dic_2_fhir;
    GRANT ALL PRIVILEGES ON DATABASE dic_2_fhir TO liquibase_user;
    CREATE DATABASE dic_2_bpe;
    GRANT ALL PRIVILEGES ON DATABASE dic_2_bpe TO liquibase_user;
    CREATE DATABASE dic_3_fhir;
    GRANT ALL PRIVILEGES ON DATABASE dic_3_fhir TO liquibase_user;
    CREATE DATABASE dic_3_bpe;
    GRANT ALL PRIVILEGES ON DATABASE dic_3_bpe TO liquibase_user;
    CREATE DATABASE dic_4_fhir;
    GRANT ALL PRIVILEGES ON DATABASE dic_4_fhir TO liquibase_user;
    CREATE DATABASE dic_4_bpe;
    GRANT ALL PRIVILEGES ON DATABASE dic_4_bpe TO liquibase_user;
    CREATE DATABASE broker_dic_5_fhir;
    GRANT ALL PRIVILEGES ON DATABASE broker_dic_5_fhir TO liquibase_user;
    CREATE DATABASE broker_dic_5_bpe;
    GRANT ALL PRIVILEGES ON DATABASE broker_dic_5_bpe TO liquibase_user;
    CREATE DATABASE broker_dic_6_fhir;
    GRANT ALL PRIVILEGES ON DATABASE broker_dic_6_fhir TO liquibase_user;
    CREATE DATABASE broker_dic_6_bpe;
    GRANT ALL PRIVILEGES ON DATABASE broker_dic_6_bpe TO liquibase_user;
    CREATE DATABASE broker_fhir;
    GRANT ALL PRIVILEGES ON DATABASE broker_fhir TO liquibase_user;
    CREATE DATABASE broker_bpe;
    GRANT ALL PRIVILEGES ON DATABASE broker_bpe TO liquibase_user;
EOSQL
