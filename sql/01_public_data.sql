-- LeakHunter · 01_public_data.sql · find the public ZIP population table (CONTRACTS §4).
-- Run in Snowsight AFTER getting "Snowflake Public Data (Free)" from Marketplace.
-- You can also just ask CoCo: "In the Snowflake Public Data (Free) database, find a table with
-- population by ZIP code (ideally by age and sex). Give me the fully qualified name and columns."

USE ROLE ACCOUNTADMIN;

-- 1. Find the listing's database name (do not rename it).
SHOW DATABASES LIKE '%PUBLIC%';

-- 2. Replace <PUBLIC_DB> below with that name, then look for ZIP / geography / population tables.
SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, ROW_COUNT, COMMENT
FROM <PUBLIC_DB>.INFORMATION_SCHEMA.TABLES
WHERE TABLE_NAME ILIKE ANY ('%ZIP%', '%GEO%', '%POPULATION%', '%DEMOGRAPH%', '%CENSUS%')
ORDER BY 1, 2;

SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE
FROM <PUBLIC_DB>.INFORMATION_SCHEMA.COLUMNS
WHERE COLUMN_NAME ILIKE ANY ('%ZIP%', '%GEO%', '%VARIABLE%', '%POPULATION%', '%VALUE%')
ORDER BY 1, 2, 3;

-- 3. Peek at the candidate and check how ZIPs are written (e.g. '85281' vs 'zip/85281').
-- SELECT * FROM <PUBLIC_DB>.<SCHEMA>.<TABLE> LIMIT 20;

-- 4. Let both roles read it (needed for A03, which runs as LH_ANALYST).
-- GRANT IMPORTED PRIVILEGES ON DATABASE <PUBLIC_DB> TO ROLE LH_ADMIN;
-- GRANT IMPORTED PRIVILEGES ON DATABASE <PUBLIC_DB> TO ROLE LH_ANALYST;

-- 5. Sanity check against our synthetic ZIPs: rural ones should have small populations.
--    Our rural ZIPs (setup/generate_data.py): 85333 85362 85332 85324 85609 85610 86343 85554 85617 85606 86434
-- SELECT <zip_col>, <population_col> FROM <PUBLIC_DB>.<SCHEMA>.<TABLE>
-- WHERE <zip_col> IN ('85333','85362','85332','85324','85609','85610','86343','85554','85617','85606','86434','85281');

-- 6. Post in the group + update CONTRACTS §4: public DB, table, ZIP column, population column,
--    and the ZIP format. Set LH_PUBLIC_ZIP_TABLE in everyone's .env.
