from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from secure_info import SecureTicketSystem, TicketInfo
import os
import uuid
import logging

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Required for session storage

ticket_system = SecureTicketSystem()

UPLOAD_FOLDER = 'static/qr_codes'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    try:
        # Check if all required fields are present
        required_fields = ['full_name', 'email', 'citizen_id', 'birth_date', 'gender', 'district', 'city', 'password']
        for field in required_fields:
            if field not in request.form:
                logging.error(f"Missing field: {field}")
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Get user data including password
        ticket_info = TicketInfo(
            full_name=request.form['full_name'],
            email=request.form['email'],
            citizen_id=request.form['citizen_id'],
            birth_date=request.form['birth_date'],
            gender=request.form['gender'],
            district=request.form['district'],
            city=request.form['city'],
            password=request.form['password']  # ✅ Fix: Include the missing password
        )

        # Generate secure ticket
        logging.info("Generating secure ticket...")
        ticket_data = ticket_system.create_secure_ticket(ticket_info)
        logging.info("Ticket successfully generated.")

        # Ensure QR code was created
        if 'qr_code' not in ticket_data or not os.path.exists(ticket_data['qr_code']):
            logging.error("QR code file was not generated.")
            return jsonify({'error': 'QR code generation failed'}), 500

        # Move QR code to static folder
        qr_filename = f"qr_{uuid.uuid4().hex}.png"
        qr_path = os.path.join(UPLOAD_FOLDER, qr_filename)
        os.rename(ticket_data['qr_code'], qr_path)

        # Store data for the next page
        session['user_info'] = ticket_info.__dict__
        session['qr_path'] = qr_filename

        return redirect(url_for('qrcode_page'))

    except Exception as e:
        logging.error(f"Error generating ticket: {e}")
        return jsonify({'error': f'Failed to generate ticket. {str(e)}'}), 500


@app.route('/scan_qr', methods=['POST'])
def scan_qr():
    try:
        scanned_data = request.form['qr_data']  # Get scanned QR data

        # Split data back into fields
        user_info_list = scanned_data.split(',')
        user_info = {
            "full_name": user_info_list[0],
            "email": user_info_list[1],
            "citizen_id": user_info_list[2],
            "birth_date": user_info_list[3],
            "gender": user_info_list[4],
            "district": user_info_list[5],
            "city": user_info_list[6],
        }

        return render_template('scan_result.html', user_info=user_info)

    except Exception as e:
        logging.error(f"Error scanning QR code: {e}")
        return jsonify({'error': 'Invalid QR code'}), 400



@app.route('/qrcode')
def qrcode_page():
    user_info = session.get('user_info', {})
    qr_path = session.get('qr_path', '')

    if not user_info or not qr_path:
        return redirect(url_for('index'))  # Redirect to home if no data found

    return render_template('qrcode.html', user_info=user_info, qr_path=qr_path)


if __name__ == '__main__':
    app.run(debug=True)
