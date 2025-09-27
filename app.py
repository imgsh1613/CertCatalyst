import os
import uuid
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
# from werkzeug.utils import secure_filename
import cloudinary
import cloudinary.uploader
import ssl
import pymysql.cursors

app = Flask(__name__)

# Use environment variables for production
# app.secret_key = os.getenv('SECRET_KEY', 'certification_tracker_secret_key') for local

secret_key = os.getenv('SECRET_KEY')
if not secret_key:
    raise ValueError("FATAL ERROR: SECRET_KEY environment variable not set.")
app.secret_key = secret_key

# app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'static/uploads/certificates')
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'jpg', 'jpeg', 'png'}
# Ensure the upload directory exists
# os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

#Cloudinary Configuration
cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET')
)
'''
# Database connection function with environment variables
def get_db_connection():
    return mysql.connector.connect(
        host = os.getenv('DB_HOST'),
        port = int(os.getenv('DB_PORT',4000)),
        user = os.getenv('DB_USER'),
        password = os.getenv('DB_PASSWORD'),
        database = os.getenv('DB_NAME'),
        ssl_ca = 'isrgrootx1.pem',
        ssl_verify_cert = True
    )
'''
def get_db_connection():
    return pymysql.connect(
        host=os.getenv('DB_HOST'),
        port=int(os.getenv('DB_PORT', 4000)),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_NAME'),
        cursorclass=pymysql.cursors.DictCursor,
        # ✅ SSL configuration for PyMySQL:
        ssl={
            'ca': 'isrgrootx1.pem'
        }
    )

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        if session['user_type'] == 'teacher':
            return redirect(url_for('teacher_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['user_id']
                session['username'] = user['username']
                session['user_type'] = user['user_type']
                session['full_name'] = user['full_name']
                
                if user['user_type'] == 'teacher':
                    return redirect(url_for('teacher_dashboard'))
                else:
                    return redirect(url_for('student_dashboard'))
            else:
                flash('Invalid username or password', 'danger')
        except Exception as e:
            flash(f'Database connection error: {str(e)}', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user_type = request.form['user_type']
        full_name = request.form['full_name']
        
        hashed_password = generate_password_hash(password)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO users (username, password, email, user_type, full_name) VALUES (%s, %s, %s, %s, %s)',
                (username, hashed_password, email, user_type, full_name)
            )
            conn.commit()
            cursor.close()
            conn.close()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash(f'Registration failed: {str(err)}', 'danger')
        except Exception as e:
            flash(f'Database connection error: {str(e)}', 'danger')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/teacher/dashboard')
def teacher_dashboard():
    if 'user_id' not in session or session['user_type'] != 'teacher':
        flash('Access denied. Please login as a teacher.', 'danger')
        return redirect(url_for('login'))
    
    teacher_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get total number of students
        cursor.execute(
            'SELECT COUNT(DISTINCT student_id) as total_students FROM teacher_student WHERE teacher_id = %s',
            (teacher_id,)
        )
        total_students = cursor.fetchone()['total_students']
        
        # Get certificates by course
        cursor.execute('''
            SELECT c.course_name, COUNT(cert.certificate_id) as total_certificates
            FROM certificates cert
            JOIN courses c ON cert.course_id = c.course_id
            JOIN teacher_student ts ON cert.student_id = ts.student_id
            WHERE ts.teacher_id = %s
            GROUP BY c.course_id
        ''', (teacher_id,))
        certificates_by_course = cursor.fetchall()
        
        # Get certificates by student
        cursor.execute('''
            SELECT u.user_id, u.full_name, COUNT(cert.certificate_id) as certificate_count
            FROM certificates cert
            JOIN users u ON cert.student_id = u.user_id
            JOIN teacher_student ts ON u.user_id = ts.student_id
            WHERE ts.teacher_id = %s
            GROUP BY u.user_id
        ''', (teacher_id,))
        certificates_by_student = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('teacher_dashboard.html', 
                              total_students=total_students,
                              certificates_by_course=certificates_by_course,
                              certificates_by_student=certificates_by_student)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return render_template('teacher_dashboard.html', 
                              total_students=0,
                              certificates_by_course=[],
                              certificates_by_student=[])

@app.route('/student/dashboard')
def student_dashboard():
    if 'user_id' not in session or session['user_type'] != 'student':
        flash('Access denied. Please login as a student.', 'danger')
        return redirect(url_for('login'))
    
    student_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get student's certificates
        cursor.execute('''
            SELECT cert.certificate_id, c.course_name, cert.certificate_name, 
                   cert.issue_date, cert.certificate_file, cert.verification_status
            FROM certificates cert
            JOIN courses c ON cert.course_id = c.course_id
            WHERE cert.student_id = %s
            ORDER BY cert.upload_date DESC
        ''', (student_id,))
        certificates = cursor.fetchall()
        
        # Get courses for upload dropdown
        cursor.execute('SELECT course_id, course_name FROM courses ORDER BY course_name')
        courses = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('student_dashboard.html', certificates=certificates, courses=courses)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return render_template('student_dashboard.html', certificates=[], courses=[])

@app.route('/upload_certificate', methods=['POST'])
def upload_certificate():
    if 'user_id' not in session or session['user_type'] != 'student':
        return jsonify({'success': False, 'message': 'Access denied'})
    
    student_id = session['user_id']
    course_id = request.form['course_id']
    certificate_name = request.form['certificate_name']
    issue_date = request.form['issue_date']
    
    # Handle file upload
    if 'certificate_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('student_dashboard'))
    
    file = request.files['certificate_file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('student_dashboard'))
    
    if file and allowed_file(file.filename):
        try:
            filename = file.filename.lower()
            print(f"Uploading file: {filename}")
            
            if filename.endswith('.pdf'):
                # Enhanced PDF upload with proper content type
                upload_result = cloudinary.uploader.upload(
                    file,
                    folder="certificates",
                    public_id=f"cert_{student_id}_{uuid.uuid4()}",
                    resource_type="raw",
                    use_filename=True,
                    unique_filename=False,
                    overwrite=True,
                    # Add these for better PDF handling
                    context={
                        "content_type": "application/pdf",
                        "original_filename": file.filename
                    },
                    # Ensure proper file extension
                    format="pdf"
                )
                
                # Log the upload result for debugging
                print(f"PDF upload successful:")
                print(f"  URL: {upload_result['secure_url']}")
                print(f"  Public ID: {upload_result['public_id']}")
                print(f"  Format: {upload_result.get('format', 'unknown')}")
                print(f"  Resource Type: {upload_result.get('resource_type', 'unknown')}")
                
            else:
                # For images
                upload_result = cloudinary.uploader.upload(
                    file,
                    folder="certificates",
                    public_id=f"cert_{student_id}_{uuid.uuid4()}",
                    resource_type="image"
                )
            
            file_url = upload_result['secure_url']
            
            # Save to database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO certificates 
                   (student_id, course_id, certificate_name, issue_date, certificate_file) 
                   VALUES (%s, %s, %s, %s, %s)''',
                (student_id, course_id, certificate_name, issue_date, file_url)
            )
            conn.commit()
            cursor.close()
            conn.close()
            
            flash('Certificate uploaded successfully!', 'success')
            
        except Exception as e:
            flash(f'Upload failed: {str(e)}', 'danger')
            print(f"Upload error: {e}")
            import traceback
            traceback.print_exc()
    else:
        flash('Invalid file type. Please upload PDF, JPG, or PNG files only.', 'danger')
    
    return redirect(url_for('student_dashboard'))

@app.route('/add_student', methods=['GET', 'POST'])
def add_student():
    if 'user_id' not in session or session['user_type'] != 'teacher':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        student_email = request.form['student_email']
        teacher_id = session['user_id']
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Find student by email
            cursor.execute('SELECT user_id FROM users WHERE email = %s AND user_type = "student"', (student_email,))
            student = cursor.fetchone()
            
            if student:
                student_id = student['user_id']
                # Check if already linked
                cursor.execute(
                    'SELECT * FROM teacher_student WHERE teacher_id = %s AND student_id = %s',
                    (teacher_id, student_id)
                )
                if cursor.fetchone():
                    flash('Student already linked to your profile', 'warning')
                else:
                    # Create link
                    cursor.execute(
                        'INSERT INTO teacher_student (teacher_id, student_id) VALUES (%s, %s)',
                        (teacher_id, student_id)
                    )
                    conn.commit()
                    flash('Student added successfully!', 'success')
            else:
                flash('No student found with that email', 'danger')
            
            cursor.close()
            conn.close()
        except Exception as e:
            flash(f'Error adding student: {str(e)}', 'danger')
        
        return redirect(url_for('teacher_dashboard'))
    
    return render_template('add_student.html')

@app.route('/view_student/<int:student_id>')
def view_student(student_id):
    if 'user_id' not in session or session['user_type'] != 'teacher':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    
    teacher_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify teacher is linked to this student
        cursor.execute(
            'SELECT * FROM teacher_student WHERE teacher_id = %s AND student_id = %s',
            (teacher_id, student_id)
        )
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            flash('Access denied: Student not linked to your profile', 'danger')
            return redirect(url_for('teacher_dashboard'))
        
        # Get student info
        cursor.execute('SELECT full_name, email FROM users WHERE user_id = %s', (student_id,))
        student = cursor.fetchone()
        
        # Get student certificates
        cursor.execute('''
            SELECT cert.certificate_id, c.course_name, cert.certificate_name, 
                   cert.issue_date, cert.certificate_file, cert.verification_status
            FROM certificates cert
            JOIN courses c ON cert.course_id = c.course_id
            WHERE cert.student_id = %s
            ORDER BY cert.upload_date DESC
        ''', (student_id,))
        certificates = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('view_student.html', student=student, certificates=certificates)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('teacher_dashboard'))

@app.route('/verify_certificate/<int:certificate_id>/<status>')
def verify_certificate(certificate_id, status):
    if 'user_id' not in session or session['user_type'] != 'teacher':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    
    if status not in ['verified', 'rejected']:
        flash('Invalid status', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            'UPDATE certificates SET verification_status = %s WHERE certificate_id = %s',
            (status, certificate_id)
        )
        conn.commit()
        cursor.close()
        conn.close()
        flash(f'Certificate {status} successfully', 'success')
    except Exception as e:
        flash(f'Error updating certificate: {str(e)}', 'danger')
    
    # Get the referer URL to redirect back to the same page
    referrer = request.referrer or url_for('teacher_dashboard')
    return redirect(referrer)

# Health check endpoint for deployment
"""
@app.route('/health')
def health_check():
    return {'status': 'healthy'}, 200
"""
"""
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    debug = os.getenv('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)
"""















