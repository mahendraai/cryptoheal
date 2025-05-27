import mysql.connector
import openai

def scan_mysql(db_config, openai_key):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()

    # Scan crypto usage
    cursor.execute("""
    SELECT ROUTINE_NAME, ROUTINE_DEFINITION 
    FROM INFORMATION_SCHEMA.ROUTINES 
    WHERE ROUTINE_DEFINITION LIKE '%AES_ENCRYPT%' 
       OR ROUTINE_DEFINITION LIKE '%SHA2%' 
       OR ROUTINE_DEFINITION LIKE '%MD5%' 
       OR ROUTINE_DEFINITION LIKE '%ENCODE%' 
       OR ROUTINE_DEFINITION LIKE '%DECODE%' 
       OR ROUTINE_DEFINITION LIKE '%DES_ENCRYPT%';
    """)
    crypto_functions = cursor.fetchall()

    # Scan sensitive columns
    cursor.execute("""
    SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE 
    FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE COLUMN_NAME LIKE '%password%' 
       OR COLUMN_NAME LIKE '%ssn%' 
       OR COLUMN_NAME LIKE '%credit%' 
       OR COLUMN_NAME LIKE '%card%' 
       OR COLUMN_NAME LIKE '%secret%';
    """)
    sensitive_columns = cursor.fetchall()

    cursor.close()
    conn.close()

    # Call OpenAI
    openai.api_key = openai_key
    prompt = f"""
    You are a MySQL security expert. Here's the scan data:

    1. Crypto functions:
    {crypto_functions}

    2. Sensitive columns:
    {sensitive_columns}

    Analyze the security of this schema. Recommend fixes.
    """

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a MySQL encryption auditor."},
            {"role": "user", "content": prompt}
        ]
    )

    ai_analysis = response['choices'][0]['message']['content']
    return crypto_functions, sensitive_columns, ai_analysis
