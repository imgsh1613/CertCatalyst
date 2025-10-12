import os
import uuid
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
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
        ssl={
            'ca': 'isrgrootx1.pem'
        }
    )

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def admin_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_type') != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def teacher_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_type') != 'teacher':
            flash('Teacher access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

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
        academic_year = request.form.get('academic_year', '')
        section = request.form.get('section', '')
        
        hashed_password = generate_password_hash(password)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO users (username, password, email, user_type, full_name, academic_year, section) 
                   VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                (username, hashed_password, email, user_type, full_name, academic_year, section)
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

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) as count FROM users WHERE user_type = "teacher"')
        total_teachers = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM users WHERE user_type = "student"')
        total_students = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM courses')
        total_courses = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM certificates')
        total_certificates = cursor.fetchone()['count']

        cursor.execute('''
            SELECT user_id, username, full_name, email, user_type, academic_year, section, created_at 
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
        academic_year = request.form.get('academic_year', '')
        section = request.form.get('section', '')
        
        hashed_password = generate_password_hash(password)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO users (username, password, email, user_type, full_name, academic_year, section) 
                   VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                (username, hashed_password, email, user_type, full_name, academic_year, section)
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
        cursor = conn.cursor()
        cursor.execute('''
            SELECT c.*, u.full_name AS created_by_name,
            COUNT(DISTINCT ca.student_id) AS enrolled_students
            FROM courses c 
            LEFT JOIN users u ON c.created_by = u.user_id 
            LEFT JOIN course_assignments ca ON c.course_id = ca.course_id
            GROUP BY c.course_id, u.full_name
            ORDER BY c.created_at DESC;
        ''')
        courses = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template('admin_courses.html', courses=courses)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return render_template('admin_courses.html', courses=[])

@app.route('/admin/edit_course/<int:course_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_course(course_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM courses WHERE course_id = %s', (course_id,))
        course = cursor.fetchone()
        
        if not course:
            cursor.close()
            conn.close()
            flash('Course not found', 'danger')
            return redirect(url_for('admin_courses'))
        
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
            return redirect(url_for('admin_courses'))
        
        cursor.close()
        conn.close()
        return render_template('admin_edit_course.html', course=course)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('admin_courses'))

@app.route('/admin/delete_course/<int:course_id>', methods=['POST'])
@admin_required
def admin_delete_course(course_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if course has assignments or certificates
        cursor.execute('SELECT COUNT(*) as count FROM course_assignments WHERE course_id = %s', (course_id,))
        assignment_count = cursor.fetchone()['count']
        
        if assignment_count > 0:
            flash('Cannot delete course with existing assignments. Please remove all assignments first.', 'danger')
        else:
            cursor.execute('DELETE FROM courses WHERE course_id = %s', (course_id,))
            conn.commit()
            flash('Course deleted successfully!', 'success')
        
        cursor.close()
        conn.close()
    except Exception as e:
        flash(f'Error deleting course: {str(e)}', 'danger')
    
    return redirect(url_for('admin_courses'))

@app.route('/admin/users')
@admin_required
def admin_users():
    user_type = request.args.get('type', 'all')
    search = request.args.get('search', '')
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = 'SELECT * FROM users WHERE 1=1'
        params = []
        
        if user_type != 'all':
            query += ' AND user_type = %s'
            params.append(user_type)
        
        if search:
            query += ' AND (full_name LIKE %s OR email LIKE %s OR username LIKE %s)'
            search_param = f'%{search}%'
            params.extend([search_param, search_param, search_param])
        
        query += ' ORDER BY created_at DESC'
        
        cursor.execute(query, params)
        users = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return render_template('admin_users.html', users=users, user_type=user_type, search=search)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return render_template('admin_users.html', users=[], user_type=user_type, search=search)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM users WHERE user_id = %s', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            cursor.close()
            conn.close()
            flash('User not found', 'danger')
            return redirect(url_for('admin_users'))
        
        if request.method == 'POST':
            full_name = request.form['full_name']
            email = request.form['email']
            username = request.form['username']
            user_type = request.form['user_type']
            academic_year = request.form.get('academic_year', '')
            section = request.form.get('section', '')
            
            # Update password only if provided
            if request.form.get('password'):
                password = generate_password_hash(request.form['password'])
                cursor.execute(
                    '''UPDATE users SET full_name = %s, email = %s, username = %s, 
                       user_type = %s, academic_year = %s, section = %s, password = %s 
                       WHERE user_id = %s''',
                    (full_name, email, username, user_type, academic_year, section, password, user_id)
                )
            else:
                cursor.execute(
                    '''UPDATE users SET full_name = %s, email = %s, username = %s, 
                       user_type = %s, academic_year = %s, section = %s 
                       WHERE user_id = %s''',
                    (full_name, email, username, user_type, academic_year, section, user_id)
                )
            
            conn.commit()
            cursor.close()
            conn.close()
            flash('User updated successfully!', 'success')
            return redirect(url_for('admin_users'))
        
        cursor.close()
        conn.close()
        return render_template('admin_edit_user.html', user=user)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('admin_users'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Prevent deleting self
        if user_id == session['user_id']:
            flash('Cannot delete your own account', 'danger')
        else:
            cursor.execute('DELETE FROM users WHERE user_id = %s', (user_id,))
            conn.commit()
            flash('User deleted successfully!', 'success')
        
        cursor.close()
        conn.close()
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/teacher_students')
@admin_required
def admin_teacher_students():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ts.*, 
                   t.full_name as teacher_name, t.email as teacher_email,
                   s.full_name as student_name, s.email as student_email,
                   s.academic_year, s.section
            FROM teacher_student ts
            JOIN users t ON ts.teacher_id = t.user_id
            JOIN users s ON ts.student_id = s.user_id
            ORDER BY t.full_name, s.full_name
        ''')
        relationships = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return render_template('admin_teacher_students.html', relationships=relationships)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return render_template('admin_teacher_students.html', relationships=[])

@app.route('/admin/remove_teacher_student/<int:teacher_id>/<int:student_id>', methods=['POST'])
@admin_required
def admin_remove_teacher_student(teacher_id, student_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Remove the relationship
        cursor.execute('DELETE FROM teacher_student WHERE teacher_id = %s AND student_id = %s', 
                      (teacher_id, student_id))
        
        # Optionally remove course assignments too
        cursor.execute('DELETE FROM course_assignments WHERE teacher_id = %s AND student_id = %s',
                      (teacher_id, student_id))
        
        conn.commit()
        cursor.close()
        conn.close()
        flash('Teacher-student relationship removed successfully!', 'success')
    except Exception as e:
        flash(f'Error removing relationship: {str(e)}', 'danger')
    
    return redirect(url_for('admin_teacher_students'))

@app.route('/teacher/dashboard')
@teacher_required
def teacher_dashboard():
    teacher_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get total students
        cursor.execute(
            'SELECT COUNT(DISTINCT student_id) as total_students FROM teacher_student WHERE teacher_id = %s',
            (teacher_id,)
        )
        total_students = cursor.fetchone()['total_students']
        
        # Get course statistics with completion rates
        cursor.execute('''
            SELECT 
                c.course_id,
                c.course_name,
                c.course_year,
                COUNT(DISTINCT ca.student_id) as total_assigned,
                COUNT(DISTINCT CASE WHEN ca.status = 'completed' THEN ca.student_id END) as completed,
                COUNT(DISTINCT CASE WHEN ca.status = 'active' THEN ca.student_id END) as pending,
                COUNT(DISTINCT CASE WHEN cert.verification_status = 'verified' THEN cert.certificate_id END) as verified_certs
            FROM courses c
            LEFT JOIN course_assignments ca ON c.course_id = ca.course_id AND ca.teacher_id = %s
            LEFT JOIN certificates cert ON ca.assignment_id = cert.assignment_id
            WHERE c.created_by = %s
            GROUP BY c.course_id, c.course_name, c.course_year
            ORDER BY c.course_name
        ''', (teacher_id, teacher_id))
        course_stats = cursor.fetchall()
        
        # Get students grouped by year and section
        cursor.execute('''
            SELECT 
                u.user_id, 
                u.full_name, 
                u.academic_year, 
                u.section,
                COUNT(DISTINCT ca.course_id) as total_courses,
                COUNT(DISTINCT CASE WHEN ca.status = 'completed' THEN ca.course_id END) as completed_courses,
                COUNT(DISTINCT CASE WHEN cert.verification_status = 'verified' THEN cert.certificate_id END) as verified_certs
            FROM users u
            JOIN teacher_student ts ON u.user_id = ts.student_id
            LEFT JOIN course_assignments ca ON u.user_id = ca.student_id AND ca.teacher_id = %s
            LEFT JOIN certificates cert ON ca.assignment_id = cert.assignment_id
            WHERE ts.teacher_id = %s AND u.user_type = 'student'
            GROUP BY u.user_id, u.full_name, u.academic_year, u.section
            ORDER BY u.academic_year, u.section, u.full_name
        ''', (teacher_id, teacher_id))
        students = cursor.fetchall()
        
        # Get unique years and sections for filtering
        cursor.execute('''
            SELECT DISTINCT academic_year, section
            FROM users u
            JOIN teacher_student ts ON u.user_id = ts.student_id
            WHERE ts.teacher_id = %s AND u.user_type = 'student'
            AND academic_year IS NOT NULL AND academic_year != ''
            ORDER BY academic_year, section
        ''', (teacher_id,))
        year_sections = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('teacher_dashboard.html', 
                              total_students=total_students,
                              course_stats=course_stats,
                              students=students,
                              year_sections=year_sections)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return render_template('teacher_dashboard.html', 
                              total_students=0,
                              course_stats=[],
                              students=[],
                              year_sections=[])

@app.route('/teacher/courses')
@teacher_required
def teacher_courses():
    teacher_id = session['user_id']
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT 
                c.*,
                COUNT(DISTINCT ca.student_id) as enrolled_students
            FROM courses c
            LEFT JOIN course_assignments ca ON c.course_id = ca.course_id
            WHERE c.created_by = %s
            GROUP BY c.course_id
            ORDER BY c.created_at DESC
        ''', (teacher_id,))
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
        cursor = conn.cursor()

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

@app.route('/teacher/assign_course/<int:student_id>', methods=['GET', 'POST'])
@teacher_required
def assign_course(student_id):
    teacher_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify teacher-student relationship
        cursor.execute(
            'SELECT * FROM teacher_student WHERE teacher_id = %s AND student_id = %s',
            (teacher_id, student_id)
        )
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            flash('Access denied', 'danger')
            return redirect(url_for('teacher_dashboard'))
        
        if request.method == 'POST':
            course_ids = request.form.getlist('course_ids')
            
            for course_id in course_ids:
                # Check if already assigned
                cursor.execute(
                    'SELECT * FROM course_assignments WHERE teacher_id = %s AND student_id = %s AND course_id = %s',
                    (teacher_id, student_id, course_id)
                )
                if not cursor.fetchone():
                    cursor.execute(
                        '''INSERT INTO course_assignments (teacher_id, student_id, course_id) 
                           VALUES (%s, %s, %s)''',
                        (teacher_id, student_id, course_id)
                    )
            
            conn.commit()
            flash('Courses assigned successfully!', 'success')
            cursor.close()
            conn.close()
            return redirect(url_for('view_student', student_id=student_id))
        
        # Get student info
        cursor.execute('SELECT * FROM users WHERE user_id = %s', (student_id,))
        student = cursor.fetchone()
        
        # Get available courses
        cursor.execute('SELECT * FROM courses WHERE created_by = %s ORDER BY course_name', (teacher_id,))
        courses = cursor.fetchall()
        
        # Get already assigned courses
        cursor.execute(
            'SELECT course_id FROM course_assignments WHERE teacher_id = %s AND student_id = %s',
            (teacher_id, student_id)
        )
        assigned_course_ids = [row['course_id'] for row in cursor.fetchall()]
        
        cursor.close()
        conn.close()
        
        return render_template('assign_course.html', 
                             student=student, 
                             courses=courses,
                             assigned_course_ids=assigned_course_ids)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('teacher_dashboard'))

@app.route('/student/dashboard')
def student_dashboard():
    if 'user_id' not in session or session['user_type'] != 'student':
        flash('Access denied. Please login as a student.', 'danger')
        return redirect(url_for('login'))
    
    student_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get assigned courses with completion status
        cursor.execute('''
            SELECT 
                ca.assignment_id,
                ca.course_id,
                c.course_name,
                c.course_description,
                c.certificate_template,
                ca.status,
                ca.assigned_date,
                ca.completion_date,
                cert.certificate_id,
                cert.certificate_name,
                cert.issue_date,
                cert.certificate_file,
                cert.verification_status
            FROM course_assignments ca
            JOIN courses c ON ca.course_id = c.course_id
            LEFT JOIN certificates cert ON ca.assignment_id = cert.assignment_id
            WHERE ca.student_id = %s
            ORDER BY ca.status, ca.assigned_date DESC
        ''', (student_id,))
        assigned_courses = cursor.fetchall()
        
        # Organize courses by status
        active_courses = []
        completed_courses = []
        
        for course in assigned_courses:
            if course['status'] == 'completed' or course['verification_status'] == 'verified':
                completed_courses.append(course)
            else:
                active_courses.append(course)
        
        cursor.close()
        conn.close()
        
        return render_template('student_dashboard.html', 
                             active_courses=active_courses,
                             completed_courses=completed_courses)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return render_template('student_dashboard.html', 
                             active_courses=[],
                             completed_courses=[])

@app.route('/upload_certificate', methods=['POST'])
def upload_certificate():
    if 'user_id' not in session or session['user_type'] != 'student':
        return jsonify({'success': False, 'message': 'Access denied'})
    
    student_id = session['user_id']
    assignment_id = request.form['assignment_id']
    certificate_name = request.form['certificate_name']
    issue_date = request.form['issue_date']

    if 'certificate_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('student_dashboard'))
    
    file = request.files['certificate_file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('student_dashboard'))
    
    if file and allowed_file(file.filename):
        try:
            # Get course_id from assignment
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT course_id FROM course_assignments WHERE assignment_id = %s AND student_id = %s',
                         (assignment_id, student_id))
            assignment = cursor.fetchone()
            
            if not assignment:
                flash('Invalid assignment', 'danger')
                cursor.close()
                conn.close()
                return redirect(url_for('student_dashboard'))
            
            upload_result = cloudinary.uploader.upload(
                file,
                folder="certificates",
                public_id=str(uuid.uuid4()),
                resource_type="auto"
            )
            file_url = upload_result['secure_url']
            
            cursor.execute(
                '''INSERT INTO certificates 
                   (student_id, course_id, assignment_id, certificate_name, issue_date, certificate_file) 
                   VALUES (%s, %s, %s, %s, %s, %s)''',
                (student_id, assignment['course_id'], assignment_id, certificate_name, issue_date, file_url)
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
        student_email = request.form.get('student_email')
        academic_year = request.form.get('academic_year')
        section = request.form.get('section')
        teacher_id = session['user_id']
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Build query based on provided filters
            query = 'SELECT user_id, full_name FROM users WHERE user_type = "student"'
            params = []
            
            if student_email:
                query += ' AND email = %s'
                params.append(student_email)
            else:
                conditions = []
                if academic_year:
                    conditions.append('academic_year = %s')
                    params.append(academic_year)
                if section:
                    conditions.append('section = %s')
                    params.append(section)
                
                if conditions:
                    query += ' AND ' + ' AND '.join(conditions)
            
            cursor.execute(query, params)
            students = cursor.fetchall()
            
            if students:
                added_count = 0
                for student in students:
                    student_id = student['user_id']
                    cursor.execute(
                        'SELECT * FROM teacher_student WHERE teacher_id = %s AND student_id = %s',
                        (teacher_id, student_id)
                    )
                    if not cursor.fetchone():
                        cursor.execute(
                            'INSERT INTO teacher_student (teacher_id, student_id) VALUES (%s, %s)',
                            (teacher_id, student_id)
                        )
                        added_count += 1
                
                conn.commit()
                if added_count > 0:
                    flash(f'{added_count} student(s) added successfully!', 'success')
                else:
                    flash('All selected students are already linked', 'warning')
            else:
                flash('No students found with the given criteria', 'danger')
            
            cursor.close()
            conn.close()
        except Exception as e:
            flash(f'Error adding student: {str(e)}', 'danger')
        
        return redirect(url_for('teacher_dashboard'))
    
    # Get available years and sections for the form
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT DISTINCT academic_year 
            FROM users 
            WHERE user_type = "student" AND academic_year IS NOT NULL AND academic_year != ""
            ORDER BY academic_year
        ''')
        years = cursor.fetchall()
        
        cursor.execute('''
            SELECT DISTINCT section 
            FROM users 
            WHERE user_type = "student" AND section IS NOT NULL AND section != ""
            ORDER BY section
        ''')
        sections = cursor.fetchall()
        
        cursor.close()
        conn.close()
    except Exception as e:
        years = []
        sections = []
    
    return render_template('add_student.html', years=years, sections=sections)

@app.route('/view_student/<int:student_id>')
@teacher_required
def view_student(student_id):
    teacher_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            'SELECT * FROM teacher_student WHERE teacher_id = %s AND student_id = %s',
            (teacher_id, student_id)
        )
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            flash('Access denied: Student not linked to your profile', 'danger')
            return redirect(url_for('teacher_dashboard'))

        cursor.execute('SELECT full_name, email, academic_year, section FROM users WHERE user_id = %s', (student_id,))
        student = cursor.fetchone()

        # Get course assignments with certificate details
        cursor.execute('''
            SELECT 
                ca.assignment_id,
                ca.course_id,
                c.course_name,
                ca.status,
                ca.assigned_date,
                ca.completion_date,
                cert.certificate_id,
                cert.certificate_name, 
                cert.issue_date, 
                cert.certificate_file, 
                cert.verification_status
            FROM course_assignments ca
            JOIN courses c ON ca.course_id = c.course_id
            LEFT JOIN certificates cert ON ca.assignment_id = cert.assignment_id
            WHERE ca.student_id = %s AND ca.teacher_id = %s
            ORDER BY ca.assigned_date DESC
        ''', (student_id, teacher_id))
        assignments = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('view_student.html', student=student, assignments=assignments, student_id=student_id)
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
        
        # Update certificate status
        cursor.execute(
            'UPDATE certificates SET verification_status = %s WHERE certificate_id = %s',
            (status, certificate_id)
        )
        
        # If verified, mark the course assignment as completed
        if status == 'verified':
            cursor.execute('''
                UPDATE course_assignments ca
                JOIN certificates cert ON ca.assignment_id = cert.assignment_id
                SET ca.status = 'completed', ca.completion_date = NOW()
                WHERE cert.certificate_id = %s
            ''', (certificate_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        flash(f'Certificate {status} successfully', 'success')
    except Exception as e:
        flash(f'Error updating certificate: {str(e)}', 'danger')

    referrer = request.referrer or url_for('teacher_dashboard')
    return redirect(referrer)
