"""Shared configuration. Reads .env once. Do not hardcode secrets anywhere else."""
import os
from dotenv import load_dotenv

load_dotenv()

ADMIN = "LH_ADMIN"
ANALYST = "LH_ANALYST"
HR = "LH_HR"
DATABASE = os.getenv("SNOWFLAKE_DATABASE", "LEAKHUNTER")
WAREHOUSE = os.getenv("SNOWFLAKE_WAREHOUSE", "LH_WH")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma3:4b")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
PUBLIC_ZIP_TABLE = os.getenv("LH_PUBLIC_ZIP_TABLE", "")


def snowflake_params() -> dict:
    """Connection params for snowflake.connector.connect (role is set by db.connect)."""
    params = {
        "account": os.environ["SNOWFLAKE_ACCOUNT"],
        "user": os.environ["SNOWFLAKE_USER"],
        "warehouse": WAREHOUSE,
        "database": DATABASE,
    }
    key_file = os.getenv("SNOWFLAKE_PRIVATE_KEY_FILE")
    if key_file:
        params["private_key_file"] = key_file
    else:
        params["password"] = os.environ["SNOWFLAKE_PASSWORD"]
    return params
