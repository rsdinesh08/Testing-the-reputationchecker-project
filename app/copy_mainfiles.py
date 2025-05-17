from flask import Flask, render_template, request
import sys
import os

# Add the absolute path of the Flask directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'Flask')))

# Import the reputation_check module
import reputation_check

app = Flask(__name__, template_folder='Flask/templates', static_folder='Flask/static')

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    if request.method == 'POST':
        user_input = request.form.get('user_input')
        
        # Check if the input is a valid URL (simple check for now)
        if user_input:
            result = reputation_check.check_reputation(user_input)
        else:
            result = {"error": "Invalid URL"}
    
    return render_template('base.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)

