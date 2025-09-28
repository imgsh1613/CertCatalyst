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

secret_key = os.getenv('SECRET_KEY')
if not secret_key:
    raise ValueError("FATAL ERROR: SECRET_KEY environment variable not set.")
app.secret_key = secret_key

app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'jpg', 'jpeg', 'png'}

cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET')
)

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

def admin_required(f):
    """Decorator to require admin access"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_type') != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def teacher_required(f):
    """Decorator to require teacher access"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_type') != 'teacher':
            flash('Teacher access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        if session['user_type'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif session['user_type'] == 'teacher':
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
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['user_id']
                session['username'] = user['username']
                session['user_type'] = user['user_type']
                session['full_name'] = user['full_name']
                
                if user['user_type'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                elif user['user_type'] == 'teacher':
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

# Admin Routes
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get statistics
        cursor.execute('SELECT COUNT(*) as count FROM users WHERE user_type = "teacher"')
        total_teachers = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM users WHERE user_type = "student"')
        total_students = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM courses')
        total_courses = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM certificates')
        total_certificates = cursor.fetchone()['count']
        
        # Get recent users
        cursor.execute('''
            SELECT user_id, username, full_name, email, user_type, created_at 
            FROM users 
            WHERE user_type IN ('teacher', 'student')
            ORDER BY created_at DESC 
            LIMIT 10
        ''')
        recent_users = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('admin_dashboard.html',
                              total_teachers=total_teachers,
                              total_students=total_students,
                              total_courses=total_courses,
                              total_certificates=total_certificates,
                              recent_users=recent_users)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return render_template('admin_dashboard.html',
                              total_teachers=0, total_students=0,
                              total_courses=0, total_certificates=0,
                              recent_users=[])

@app.route('/admin/create_user', methods=['GET', 'POST'])
@admin_required
def admin_create_user():
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
            flash(f'{user_type.title()} created successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except mysql.connector.Error as err:
            flash(f'User creation failed: {str(err)}', 'danger')
        except Exception as e:
            flash(f'Database error: {str(e)}', 'danger')
    
    return render_template('admin_create_user.html')

@app.route('/admin/courses')
@admin_required
def admin_courses():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT c.*, u.full_name as created_by_name 
            FROM courses c 
            LEFT JOIN users u ON c.created_by = u.user_id 
            ORDER BY c.created_at DESC
        ''')
        courses = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template('admin_courses.html', courses=courses)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return render_template('admin_courses.html', courses=[])

# Teacher Routes
@app.route('/teacher/dashboard')
@teacher_required
def teacher_dashboard():
    teacher_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
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

@app.route('/teacher/courses')
@teacher_required
def teacher_courses():
    teacher_id = session['user_id']
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM courses WHERE created_by = %s ORDER BY created_at DESC', (teacher_id,))
        courses = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template('teacher_courses.html', courses=courses)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return render_template('teacher_courses.html', courses=[])

@app.route('/teacher/add_course', methods=['GET', 'POST'])
@teacher_required
def teacher_add_course():
    if request.method == 'POST':
        course_name = request.form['course_name']
        course_description = request.form['course_description']
        certificate_template = request.form['certificate_template']
        course_year = request.form['course_year']
        teacher_id = session['user_id']
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO courses (course_name, course_description, certificate_template, course_year, created_by) 
                   VALUES (%s, %s, %s, %s, %s)''',
                (course_name, course_description, certificate_template, course_year, teacher_id)
            )
            conn.commit()
            cursor.close()
            conn.close()
            flash('Course added successfully!', 'success')
            return redirect(url_for('teacher_courses'))
        except Exception as e:
            flash(f'Error adding course: {str(e)}', 'danger')
    
    return render_template('teacher_add_course.html')

@app.route('/teacher/edit_course/<int:course_id>', methods=['GET', 'POST'])
@teacher_required
def teacher_edit_course(course_id):
    teacher_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Verify teacher owns this course
        cursor.execute('SELECT * FROM courses WHERE course_id = %s AND created_by = %s', (course_id, teacher_id))
        course = cursor.fetchone()
        
        if not course:
            cursor.close()
            conn.close()
            flash('Course not found or access denied', 'danger')
            return redirect(url_for('teacher_courses'))
        
        if request.method == 'POST':
            course_name = request.form['course_name']
            course_description = request.form['course_description']
            certificate_template = request.form['certificate_template']
            course_year = request.form['course_year']
            
            cursor.execute(
                '''UPDATE courses SET course_name = %s, course_description = %s, 
                   certificate_template = %s, course_year = %s WHERE course_id = %s''',
                (course_name, course_description, certificate_template, course_year, course_id)
            )
            conn.commit()
            cursor.close()
            conn.close()
            flash('Course updated successfully!', 'success')
            return redirect(url_for('teacher_courses'))
        
        cursor.close()
        conn.close()
        return render_template('teacher_edit_course.html', course=course)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('teacher_courses'))

@app.route('/student/dashboard')
def student_dashboard():
    if 'user_id' not in session or session['user_type'] != 'student':
        flash('Access denied. Please login as a student.', 'danger')
        return redirect(url_for('login'))
    
    student_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
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
            # Upload file to Cloudinary
            upload_result = cloudinary.uploader.upload(
                file,
                folder="certificates",
                public_id=str(uuid.uuid4()),
                resource_type="auto"
            )
            file_url = upload_result['secure_url']  # Cloudinary hosted URL
            
            # Save to database with Cloudinary URL
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
    else:
        flash('Invalid file type', 'danger')
    
    return redirect(url_for('student_dashboard'))

@app.route('/add_student', methods=['GET', 'POST'])
@teacher_required
def add_student():
    if request.method == 'POST':
        student_email = request.form['student_email']
        teacher_id = session['user_id']
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            
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
@teacher_required
def view_student(student_id):
    teacher_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
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
@teacher_required
def verify_certificate(certificate_id, status):
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



















