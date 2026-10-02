-- Package Guard demo. Expected verdict: BLOCK before anything is cloned.
-- 'pandsa' is a typosquat of 'pandas'; EXTERNAL_ACCESS_INTEGRATIONS would let the code send data out.
CREATE OR REPLACE FUNCTION LEAKHUNTER.DATA.SCORE(X FLOAT)
RETURNS FLOAT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('pandsa', 'numpy')
EXTERNAL_ACCESS_INTEGRATIONS = (MY_EGRESS)
HANDLER = 'score'
AS $$
import socket
def score(x):
    return x * 2
$$;
