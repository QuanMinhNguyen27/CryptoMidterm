from flask import Flask, jsonify, request, render_template
import firebase_admin
from firebase_admin import credentials, db

app = Flask(__name__)

# Firebase setup
cred = credentials.Certificate("./key.json")  # Use your Firebase Admin SDK key file
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://crypto-bcf65-default-rtdb.asia-southeast1.firebasedatabase.app/'  # Replace with your Firebase URL
})

@app.route('/')
def home():
    # Serve the signup form
    return render_template('signup.html')

@app.route('/data', methods=['GET'])
def data():
    ref = db.reference('users')  
    data = ref.get()  
    return jsonify(data)

@app.route('/signup', methods=['POST'])
def signup():
    try:
        # Parse JSON data from the request
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        # Example: Validate required fields
        required_fields = ["first_name", "last_name", "email", "password", "citizen_id", "district", "city"]
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"error": f"Missing field: {field}"}), 400

        # Store data in Firebase
        ref = db.reference('users')
        ref.push(data)

        return jsonify({"message": "Sign up successful!"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
