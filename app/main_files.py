from flask import Flask, render_template, request
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'Flask')))

import reputation_check

app = Flask(__name__, template_folder='Flask/templates', static_folder='Flask/static')

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    if request.method == 'POST':
        # Get the URL input from the user
        user_input = request.form.get('user_input')

        if user_input:
            # Call the reputation_check function with the user input
            result = reputation_check.check_reputation(user_input)
        else:
            # If the URL is invalid or empty
            result = {"error": "Invalid URL"}

    return render_template('base.html', result=result)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)

