from flask import Flask, render_template, request
from scanner import scan_mysql

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        host = request.form['host']
        user = request.form['user']
        password = request.form['password']
        database = request.form['database']
        openai_key = request.form['openai_key']

        db_config = {
            "host": host,
            "user": user,
            "password": password,
            "database": database
        }

        try:
            crypto_funcs, sensitive_cols, ai_report = scan_mysql(db_config, openai_key)
            result = {
                "crypto_funcs": crypto_funcs,
                "sensitive_cols": sensitive_cols,
                "ai_report": ai_report
            }
        except Exception as e:
            result = {"error": str(e)}

    return render_template('index.html', result=result)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
