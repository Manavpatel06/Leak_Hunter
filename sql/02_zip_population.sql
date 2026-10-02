-- LeakHunter · 02_zip_population.sql · public ZIP population for the re-identification attack (A03).
-- Source: Snowflake Public Data (Free) from Marketplace -> US Census American Community Survey (ACS).
-- Run top to bottom in Snowsight (Run All). Safe to re-run.

-- 1. Let LH_ADMIN read the shared public database.
USE ROLE ACCOUNTADMIN;
GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE_PUBLIC_DATA_FREE TO ROLE LH_ADMIN;

-- 2. Confirm the variable is "Total Population" (expect 1 row: B01003_001E_5YR | Total Population ... 5yr Estimate).
SELECT VARIABLE, VARIABLE_NAME
FROM SNOWFLAKE_PUBLIC_DATA_FREE.PUBLIC_DATA_FREE.AMERICAN_COMMUNITY_SURVEY_ATTRIBUTES
WHERE VARIABLE = 'B01003_001E_5YR';

-- 3. One row per Arizona ZIP (85xxx-86xxx), latest ACS 5-year estimate. GEO_ID looks like 'zip/85281'.
--    Copied into LEAKHUNTER so the analyst never needs access to the shared database itself.
USE ROLE LH_ADMIN;
USE WAREHOUSE LH_WH;
CREATE OR REPLACE TABLE LEAKHUNTER.DATA.ZIP_POPULATION
  COMMENT = 'Public: ACS total population by ZIP (Snowflake Public Data Free, B01003_001E_5YR)' AS
SELECT REPLACE(GEO_ID, 'zip/', '') AS ZIP,
       VALUE::INT                  AS POPULATION,
       DATE                        AS AS_OF
FROM SNOWFLAKE_PUBLIC_DATA_FREE.PUBLIC_DATA_FREE.AMERICAN_COMMUNITY_SURVEY_TIMESERIES
WHERE VARIABLE = 'B01003_001E_5YR'
  AND GEO_ID BETWEEN 'zip/85000' AND 'zip/86599'
QUALIFY ROW_NUMBER() OVER (PARTITION BY GEO_ID ORDER BY DATE DESC) = 1;

-- Public data is fine for the analyst to read (it is the attacker's "outside" dataset).
GRANT SELECT ON TABLE LEAKHUNTER.DATA.ZIP_POPULATION TO ROLE LH_ANALYST;

-- 4. Checks
-- a) ~400 Arizona ZIPs expected
SELECT COUNT(*) AS AZ_ZIPS, MIN(AS_OF), MAX(AS_OF) FROM LEAKHUNTER.DATA.ZIP_POPULATION;
-- b) our rural ZIPs should be small (< 5,000); 85281 (Tempe) should be large
SELECT ZIP, POPULATION FROM LEAKHUNTER.DATA.ZIP_POPULATION
WHERE ZIP IN ('85333','85362','85332','85324','85609','85610','86343','85554','85617','85606','86434','85281')
ORDER BY POPULATION;
-- c) MUST return 0 rows: masked ZIPs look like '85200', so no real ZIP may end in '00'
--    (otherwise A03 could still "match" after the fix)
SELECT ZIP FROM LEAKHUNTER.DATA.ZIP_POPULATION WHERE ZIP LIKE '%00';
-- d) the re-identification itself, as admin (expect > 0 while L3 is planted)
SELECT COUNT(*) AS REIDENTIFIABLE
FROM (SELECT ZIP, YEAR(DOB) AS BIRTH_YEAR, SEX
      FROM LEAKHUNTER.DATA.PATIENT_DEMOGRAPHICS GROUP BY 1, 2, 3 HAVING COUNT(*) = 1) U
JOIN LEAKHUNTER.DATA.ZIP_POPULATION P ON P.ZIP = U.ZIP
WHERE P.POPULATION < 5000;
