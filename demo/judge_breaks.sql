-- Judge-breaks-it options. Run ONE as LH_ADMIN in Snowsight during the demo, then run a round.
USE ROLE LH_ADMIN;

-- Option 1: someone exports a table "just for a quick analysis" (caught by A07 sweep)
CREATE OR REPLACE TABLE LEAKHUNTER.SCRATCH.JUDGE_EXPORT AS SELECT * FROM LEAKHUNTER.DATA.PATIENTS;
GRANT USAGE ON SCHEMA LEAKHUNTER.SCRATCH TO ROLE LH_ANALYST;
GRANT SELECT ON TABLE LEAKHUNTER.SCRATCH.JUDGE_EXPORT TO ROLE LH_ANALYST;

-- Option 2: someone gives the analyst team HR access "temporarily" (caught by A04)
-- GRANT ROLE LH_HR TO ROLE LH_ANALYST;

-- Option 3: someone removes the SSN mask while debugging (caught by A01)
-- ALTER TABLE LEAKHUNTER.DATA.PATIENTS MODIFY COLUMN SSN UNSET MASKING POLICY;
