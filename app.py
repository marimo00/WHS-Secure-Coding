import sqlite3
import uuid
import re
import os
import bcrypt
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
from flask_socketio import SocketIO, send, join_room, emit
from datetime import datetime, timedelta
from html import escape
from functools import wraps
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # 24바이트 랜덤 키 생성
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # 세션 타임아웃 1시간
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS에서만 쿠키 전송
app.config['SESSION_COOKIE_HTTPONLY'] = True  # JavaScript로 쿠키 접근 방지
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF 공격 방지
DATABASE = 'market.db'
socketio = SocketIO(app)
csrf = CSRFProtect(app)  # CSRF 보호 활성화

# 접근 제어 데코레이터들
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
            
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        if not user or not user['is_admin']:
            flash('관리자 권한이 필요합니다.')
            return redirect(url_for('dashboard'))
            
        return f(*args, **kwargs)
    return decorated_function

def check_banned(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return f(*args, **kwargs)
            
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT is_banned FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        if user and user['is_banned']:
            flash('이 계정은 관리자에 의해 차단되었습니다.')
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

def seller_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
            
        db = get_db()
        cursor = db.cursor()
        
        # URL 파라미터에서 product_id 가져오기
        product_id = kwargs.get('product_id')
        if not product_id:
            flash('상품을 찾을 수 없습니다.')
            return redirect(url_for('dashboard'))
            
        cursor.execute("SELECT seller_id FROM product WHERE id = ?", (product_id,))
        product = cursor.fetchone()
        
        if not product or product['seller_id'] != session['user_id']:
            flash('권한이 없습니다.')
            return redirect(url_for('dashboard'))
            
        return f(*args, **kwargs)
    return decorated_function

# 전역 요청 전처리기
@app.before_request
def before_request():
    if 'user_id' in session:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT is_banned FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        if user and user['is_banned'] and request.endpoint not in ['login', 'logout']:
            flash('이 계정은 관리자에 의해 차단되었습니다.')
            return redirect(url_for('login'))

@app.after_request
def add_security_headers(response):
    # XSS 방지
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # 클릭재킹 방지
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # MIME 타입 스니핑 방지
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # CSP (콘텐츠 보안 정책)
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:;"
    )
    response.headers['Content-Security-Policy'] = csp
    return response

# XSS 방지 유틸리티 함수들
def sanitize_input(input_str):
    """사용자 입력을 검증하고 이스케이프 처리"""
    if not input_str:
        return ""
    # HTML 이스케이프 처리
    return escape(input_str)

def validate_username(username):
    """사용자명 검증"""
    if not username:
        return False
    # 영문, 숫자, 언더스코어만 허용 (3-20자)
    return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username))

def validate_password(password):
    """비밀번호 검증"""
    if not password:
        return False
    # 최소 8자, 영문, 숫자, 특수문자 포함
    return bool(re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', password))

def validate_price(price):
    """가격 검증"""
    try:
        price = int(price)
        return price > 0
    except (ValueError, TypeError):
        return False

def validate_bio(bio):
    """자기소개 검증"""
    if not bio:
        return True
    # 최대 500자
    return len(bio) <= 500

def validate_message(message):
    """채팅 메시지 검증"""
    if not message:
        return False
    # 최대 1000자
    return len(message) <= 1000

# 숫자 포맷팅 필터 추가
@app.template_filter('number_format')
def number_format(value):
    if value is None:
        return "0"
    return "{:,}".format(value)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_admin INTEGER DEFAULT 0,
                is_banned INTEGER DEFAULT 0,
                balance INTEGER DEFAULT 0,
                account_number TEXT
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price INTEGER NOT NULL,
                seller_id TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_banned INTEGER DEFAULT 0,
                is_sold INTEGER DEFAULT 0,
                FOREIGN KEY (seller_id) REFERENCES user (id)
            )
        """)
        # 채팅방 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_room (
                id TEXT PRIMARY KEY,
                user1_id TEXT NOT NULL,
                user2_id TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user1_id) REFERENCES user(id),
                FOREIGN KEY (user2_id) REFERENCES user(id)
            )
        """)
        # 채팅 메시지 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_message (
                id TEXT PRIMARY KEY,
                room_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                message TEXT NOT NULL,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (room_id) REFERENCES chat_room(id),
                FOREIGN KEY (sender_id) REFERENCES user(id)
            )
        """)
        # 거래 내역 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                type TEXT NOT NULL,  -- 'transfer', 'deposit', 'withdraw'
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES user (id),
                FOREIGN KEY (receiver_id) REFERENCES user (id)
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_handled INTEGER DEFAULT 0,
                FOREIGN KEY (reporter_id) REFERENCES user (id)
            )
        """)
        
        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # 입력 검증
        if not validate_username(username):
            flash('사용자명은 영문, 숫자, 언더스코어만 사용 가능하며 3-20자여야 합니다.')
            return redirect(url_for('register'))
        
        if not validate_password(password):
            flash('비밀번호는 최소 8자 이상이며 영문, 숫자, 특수문자를 포함해야 합니다.')
            return redirect(url_for('register'))
        
        db = get_db()
        cursor = db.cursor()
        
        # username 중복 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('이미 사용 중인 사용자명입니다.')
            return redirect(url_for('register'))
        
        # 비밀번호 해싱
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # 입력 검증
        if not validate_username(username) or not password:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
            
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            if user['is_banned']:
                flash('이 계정은 관리자에 의해 차단되었습니다.')
                return redirect(url_for('login'))
            
            session['user_id'] = user['id']
            flash('로그인 성공!')
            if user['is_admin']:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
@login_required
@check_banned
def dashboard():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    cursor.execute("""
        SELECT p.*, u.username as seller_name 
        FROM product p
        JOIN user u ON p.seller_id = u.id
        WHERE p.is_banned = 0 AND p.is_sold = 0
        ORDER BY p.created_at DESC LIMIT 6
    """)
    recent_products = cursor.fetchall()
    return render_template('dashboard.html', products=recent_products, user=current_user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
@login_required
@check_banned
def profile():
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        
        # bio 검증
        if not validate_bio(bio):
            flash('자기소개는 최대 500자까지 입력 가능합니다.')
            return redirect(url_for('profile'))
        
        # bio 이스케이프 처리
        bio = sanitize_input(bio)
        
        # 현재 비밀번호 확인
        cursor.execute("SELECT password FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        if current_password and new_password:
            if not bcrypt.checkpw(current_password.encode('utf-8'), user['password']):
                flash('현재 비밀번호가 일치하지 않습니다.')
                return redirect(url_for('profile'))
            
            if not validate_password(new_password):
                flash('새 비밀번호는 최소 8자 이상이며 영문, 숫자, 특수문자를 포함해야 합니다.')
                return redirect(url_for('profile'))
            
            hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("UPDATE user SET password = ? WHERE id = ?", 
                         (hashed_new_password, session['user_id']))
            flash('비밀번호가 변경되었습니다.')
        
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
@login_required
@check_banned
def new_product():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        
        # 입력 검증
        if not title or not description:
            flash('제목과 설명을 모두 입력해주세요.')
            return redirect(url_for('new_product'))
            
        if not validate_price(price):
            flash('가격은 0보다 큰 정수여야 합니다.')
            return redirect(url_for('new_product'))
        
        # 이스케이프 처리
        title = sanitize_input(title)
        description = sanitize_input(description)
        
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
@login_required
@check_banned
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    # 상품 정보와 판매자 username을 함께 조회
    cursor.execute("""
        SELECT p.*, u.username as seller_username
        FROM product p
        JOIN user u ON p.seller_id = u.id
        WHERE p.id = ?
    """, (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    return render_template('view_product.html', product=product)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
@login_required
@check_banned
def report():
    if request.method == 'POST':
        target_type = request.form['target_type']
        reason = request.form['reason']
        
        db = get_db()
        cursor = db.cursor()
        
        if target_type == 'user':
            target_username = request.form['target_username']
            # 신고 대상 사용자 조회
            cursor.execute("SELECT id FROM user WHERE username = ?", (target_username,))
            target = cursor.fetchone()
            if not target:
                flash('존재하지 않는 사용자입니다.')
                return redirect(url_for('report'))
            target_id = target['id']
        else:  # product
            target_id = request.form['target_id']
            # 신고 대상 상품 조회
            cursor.execute("SELECT id FROM product WHERE id = ?", (target_id,))
            if not cursor.fetchone():
                flash('존재하지 않는 상품입니다.')
                return redirect(url_for('report'))
        
        # 이미 신고한 적이 있는지 확인
        cursor.execute("""
            SELECT * FROM report 
            WHERE reporter_id = ? AND target_id = ? AND target_type = ? AND is_handled = 0
        """, (session['user_id'], target_id, target_type))
        
        if cursor.fetchone():
            flash('이미 신고한 대상입니다.')
            return redirect(url_for('report'))
        
        report_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO report (id, reporter_id, target_id, target_type, reason)
            VALUES (?, ?, ?, ?, ?)
        """, (report_id, session['user_id'], target_id, target_type, reason))
        db.commit()
        
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    
    return render_template('report.html')

# 관리자 페이지
@app.route('/admin')
@admin_required
@check_banned
def admin_dashboard():
    db = get_db()
    cursor = db.cursor()
    
    # 미처리 신고 수 조회
    cursor.execute("SELECT COUNT(*) FROM report WHERE is_handled = 0")
    pending_reports_count = cursor.fetchone()[0]
    
    # 차단된 사용자 수 조회
    cursor.execute("SELECT COUNT(*) FROM user WHERE is_banned = 1")
    banned_users_count = cursor.fetchone()[0]
    
    # 차단된 상품 수 조회
    cursor.execute("SELECT COUNT(*) FROM product WHERE is_banned = 1")
    banned_products_count = cursor.fetchone()[0]
    
    # 사용자 목록 조회
    cursor.execute("""
        SELECT u.*, 
               (SELECT COUNT(*) FROM report WHERE target_id = u.id AND target_type = 'user' AND is_handled = 0) as pending_reports
        FROM user u
        ORDER BY u.created_at DESC
    """)
    users = cursor.fetchall()
    
    # 상품 목록 조회
    cursor.execute("""
        SELECT p.*, u.username as seller_name,
               (SELECT COUNT(*) FROM report WHERE target_id = p.id AND target_type = 'product' AND is_handled = 0) as pending_reports
        FROM product p
        JOIN user u ON p.seller_id = u.id
        ORDER BY p.created_at DESC
    """)
    products = cursor.fetchall()
    
    return render_template('admin.html',
                         pending_reports_count=pending_reports_count,
                         banned_users_count=banned_users_count,
                         banned_products_count=banned_products_count,
                         users=users,
                         products=products)

# 사용자 차단/해제
@app.route('/admin/toggle_ban/<user_id>', methods=['POST'])
@admin_required
@check_banned
def toggle_ban(user_id):
    db = get_db()
    cursor = db.cursor()
    
    # 사용자 차단 상태 토글
    cursor.execute("UPDATE user SET is_banned = NOT is_banned WHERE id = ?", (user_id,))
    db.commit()
    
    return jsonify({'success': True})

# 상품 차단/해제
@app.route('/admin/ban_product/<product_id>', methods=['POST'])
@admin_required
@check_banned
def ban_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    ban = request.form.get('ban') == 'true'
    cursor.execute("UPDATE product SET is_banned = ? WHERE id = ?", (1 if ban else 0, product_id))
    db.commit()
    
    return jsonify({'success': True})

# 전체 채팅 메시지 처리
@socketio.on('send_message')
def handle_send_message(data):
    data['message_id'] = str(uuid.uuid4())
    data['sender_id'] = session['user_id']
    data['sent_at'] = datetime.now().isoformat()
    send(data, broadcast=True)

# 1:1 채팅방
@app.route('/chat/<username>')
@login_required
@check_banned
def chat_room(username):
    db = get_db()
    cursor = db.cursor()
    
    # 상대방 정보 조회
    cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
    other_user = cursor.fetchone()
    if not other_user:
        flash('존재하지 않는 사용자입니다.')
        return redirect(url_for('dashboard'))
    
    # 자기 자신과의 채팅 방지
    if other_user['id'] == session['user_id']:
        flash('자기 자신과는 채팅할 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 채팅방 ID 생성
    user_ids = sorted([session['user_id'], other_user['id']])
    room_id = f"chat_{user_ids[0]}_{user_ids[1]}"
    
    # 채팅방 조회 또는 생성
    cursor.execute("SELECT id FROM chat_room WHERE id = ?", (room_id,))
    room = cursor.fetchone()
    
    if not room:
        cursor.execute("""
            INSERT INTO chat_room (id, user1_id, user2_id)
            VALUES (?, ?, ?)
        """, (room_id, user_ids[0], user_ids[1]))
        db.commit()
    
    # 채팅 메시지 조회
    cursor.execute("""
        SELECT cm.*, u.username as sender_name
        FROM chat_message cm
        JOIN user u ON cm.sender_id = u.id
        WHERE cm.room_id = ?
        ORDER BY cm.sent_at ASC
    """, (room_id,))
    messages = cursor.fetchall()
    
    return render_template('chat.html', room_id=room_id, messages=messages, other_user=other_user)

# 소켓 이벤트 핸들러
@socketio.on('join_room')
def handle_join_room(data):
    room_id = data['room_id']
    join_room(room_id)

@socketio.on('private_message')
def handle_private_message(data):
    if 'user_id' not in session:
        return
    
    room_id = data['room_id']
    message = data['message']
    
    # 메시지 검증
    if not validate_message(message):
        return
    
    # 메시지 이스케이프 처리
    message = sanitize_input(message)
    
    db = get_db()
    cursor = db.cursor()
    
    # 메시지 저장
    message_id = str(uuid.uuid4())
    cursor.execute("""
        INSERT INTO chat_message (id, room_id, sender_id, message)
        VALUES (?, ?, ?, ?)
    """, (message_id, room_id, session['user_id'], message))
    db.commit()
    
    # 메시지 정보 조회
    cursor.execute("""
        SELECT cm.*, u.username as sender_name
        FROM chat_message cm
        JOIN user u ON cm.sender_id = u.id
        WHERE cm.id = ?
    """, (message_id,))
    message_data = cursor.fetchone()
    
    # 메시지 전송
    emit('private_message', {
        'message_id': message_id,
        'sender_id': session['user_id'],
        'sender_name': message_data['sender_name'],
        'message': message,
        'sent_at': message_data['sent_at']
    }, room=room_id)

# 송금 기능
@app.route('/transfer', methods=['POST'])
@login_required
@check_banned
def transfer():
    receiver_id = request.form['receiver_id']
    amount = int(request.form['amount'])
    
    db = get_db()
    cursor = db.cursor()
    
    # 잔액 확인
    cursor.execute("SELECT balance FROM user WHERE id = ?", (session['user_id'],))
    sender_balance = cursor.fetchone()['balance']
    
    if sender_balance < amount:
        return jsonify({'error': '잔액이 부족합니다.'}), 400
    
    # 송금 처리
    transaction_id = str(uuid.uuid4())
    cursor.execute("""
        INSERT INTO transactions (id, sender_id, receiver_id, amount)
        VALUES (?, ?, ?, ?)
    """, (transaction_id, session['user_id'], receiver_id, amount))
    
    # 잔액 업데이트
    cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", 
                  (amount, session['user_id']))
    cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", 
                  (amount, receiver_id))
    
    db.commit()
    return jsonify({'success': True})

# 통합 검색
@app.route('/search')
@login_required
@check_banned
def search():
    query = request.args.get('q', '')
    db = get_db()
    cursor = db.cursor()
    
    # 사용자 검색
    cursor.execute("""
        SELECT id, username 
        FROM user 
        WHERE username LIKE ? AND id != ?
        LIMIT 5
    """, (f'%{query}%', session['user_id']))
    users = cursor.fetchall()
    
    # 상품 검색
    cursor.execute("""
        SELECT p.id, p.title, p.price, u.username as seller_name
        FROM product p
        JOIN user u ON p.seller_id = u.id
        WHERE (p.title LIKE ? OR p.description LIKE ?)
        AND p.is_banned = 0 AND p.is_sold = 0
        LIMIT 5
    """, (f'%{query}%', f'%{query}%'))
    products = cursor.fetchall()
    
    return jsonify({
        'users': [{'id': user['id'], 'username': user['username']} for user in users],
        'products': [{'id': product['id'], 'title': product['title'], 'price': product['price']} for product in products]
    })

# 사용자 프로필 조회
@app.route('/user/<username>')
@login_required
@check_banned
def view_user_profile(username):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if not user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 사용자가 판매한 상품 목록 조회
    cursor.execute("SELECT * FROM product WHERE seller_id = ?", (user['id'],))
    user_products = cursor.fetchall()
    
    return render_template('user_profile.html', user=user, products=user_products)

# 사용자 검색
@app.route('/search_users', methods=['GET'])
@login_required
@check_banned
def search_users():
    query = request.args.get('q', '')
    db = get_db()
    cursor = db.cursor()
    
    if query:
        cursor.execute("SELECT * FROM user WHERE username LIKE ? AND id != ?", 
                      (f'%{query}%', session['user_id']))
    else:
        cursor.execute("SELECT * FROM user WHERE id != ?", (session['user_id'],))
    
    users = cursor.fetchall()
    return jsonify([{'id': user['id'], 'username': user['username']} for user in users])

# 내 상품 관리 페이지
@app.route('/my_products')
@login_required
@check_banned
def my_products():
    db = get_db()
    cursor = db.cursor()
    
    # 현재 사용자가 등록한 상품만 조회
    cursor.execute("""
        SELECT * FROM product 
        WHERE seller_id = ? 
        ORDER BY created_at DESC
    """, (session['user_id'],))
    products = cursor.fetchall()
    
    return render_template('my_products.html', products=products)

# 상품 수정
@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
@login_required
@check_banned
@seller_required
def edit_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        
        # 입력 검증
        if not title or not description:
            flash('제목과 설명을 모두 입력해주세요.')
            return redirect(url_for('edit_product', product_id=product_id))
            
        if not validate_price(price):
            flash('가격은 0보다 큰 정수여야 합니다.')
            return redirect(url_for('edit_product', product_id=product_id))
        
        # 이스케이프 처리
        title = sanitize_input(title)
        description = sanitize_input(description)
        
        cursor.execute("""
            UPDATE product 
            SET title = ?, description = ?, price = ?
            WHERE id = ?
        """, (title, description, price, product_id))
        db.commit()
        
        flash('상품이 수정되었습니다.')
        return redirect(url_for('my_products'))
    
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('my_products'))
    
    return render_template('edit_product.html', product=product)

# 상품 삭제
@app.route('/product/<product_id>/delete', methods=['POST'])
@login_required
@check_banned
@seller_required
def delete_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('my_products'))

# 상품 목록 페이지
@app.route('/products')
@login_required
@check_banned
def product_list():
    db = get_db()
    cursor = db.cursor()
    
    # 모든 상품 조회 (최신순, 거래 완료되지 않은 상품만)
    cursor.execute("""
        SELECT p.*, u.username as seller_name 
        FROM product p
        JOIN user u ON p.seller_id = u.id
        WHERE p.is_banned = 0 AND p.is_sold = 0
        ORDER BY p.created_at DESC
    """)
    products = cursor.fetchall()
    
    return render_template('product_list.html', products=products)

# 관리자 신고 목록
@app.route('/admin/reports')
@admin_required
@check_banned
def admin_reports():
    db = get_db()
    cursor = db.cursor()
    
    # 미처리된 신고 목록 조회
    cursor.execute("""
        SELECT r.*, 
               u1.username as reporter_name,
               CASE 
                   WHEN r.target_type = 'user' THEN u2.username
                   WHEN r.target_type = 'product' THEN p.title
               END as target_name
        FROM report r
        JOIN user u1 ON r.reporter_id = u1.id
        LEFT JOIN user u2 ON r.target_type = 'user' AND r.target_id = u2.id
        LEFT JOIN product p ON r.target_type = 'product' AND r.target_id = p.id
        WHERE r.is_handled = 0
        ORDER BY r.created_at DESC
    """)
    reports = cursor.fetchall()
    
    return render_template('admin_reports.html', reports=reports)

# 신고 처리
@app.route('/admin/handle_report/<report_id>', methods=['POST'])
@admin_required
@check_banned
def handle_report(report_id):
    db = get_db()
    cursor = db.cursor()
    
    # 신고 정보 조회
    cursor.execute("""
        SELECT r.*, u.username as target_username
        FROM report r
        JOIN user u ON r.target_id = u.id
        WHERE r.id = ?
    """, (report_id,))
    report = cursor.fetchone()
    
    if not report:
        return jsonify({'error': '신고를 찾을 수 없습니다.'}), 404
    
    action = request.form.get('action')
    
    if action == 'ban':
        # 사용자 차단
        cursor.execute("UPDATE user SET is_banned = 1 WHERE id = ?", (report['target_id'],))
        # 해당 사용자의 모든 상품도 차단
        cursor.execute("UPDATE product SET is_banned = 1 WHERE seller_id = ?", (report['target_id'],))
    
    # 신고 처리 완료 표시
    cursor.execute("UPDATE report SET is_handled = 1 WHERE id = ?", (report_id,))
    db.commit()
    
    return jsonify({'success': True})

@app.route('/admin/delete_product/<product_id>', methods=['POST'])
@admin_required
@check_banned
def admin_delete_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    
    return jsonify({'success': True})

@app.route('/wallet', methods=['GET', 'POST'])
@login_required
@check_banned
def wallet():
    db = get_db()
    cursor = db.cursor()
    
    if request.method == 'POST':
        action = request.form['action']
        password = request.form['password']
        amount = int(request.form['amount'])
        
        # 비밀번호 확인
        cursor.execute("SELECT password FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
            flash('비밀번호가 일치하지 않습니다.')
            return redirect(url_for('wallet'))
        
        if action == 'deposit':
            account_number = request.form['account_number']
            cursor.execute("""
                UPDATE user 
                SET balance = balance + ? 
                WHERE id = ?
            """, (amount, session['user_id']))
            
            # 거래 내역 기록
            transaction_id = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO transactions (id, sender_id, receiver_id, amount, type)
                VALUES (?, ?, ?, ?, 'deposit')
            """, (transaction_id, session['user_id'], session['user_id'], amount))
            
            flash(f'{amount}원이 충전되었습니다.')
            
        elif action == 'withdraw':
            account_number = request.form['account_number']
            # 잔액 확인
            cursor.execute("SELECT balance FROM user WHERE id = ?", (session['user_id'],))
            balance = cursor.fetchone()['balance']
            if balance < amount:
                flash('잔액이 부족합니다.')
                return redirect(url_for('wallet'))
            
            cursor.execute("""
                UPDATE user 
                SET balance = balance - ? 
                WHERE id = ?
            """, (amount, session['user_id']))
            
            # 거래 내역 기록
            transaction_id = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO transactions (id, sender_id, receiver_id, amount, type)
                VALUES (?, ?, ?, ?, 'withdraw')
            """, (transaction_id, session['user_id'], session['user_id'], amount))
            
            flash(f'{amount}원이 출금되었습니다.')
            
        elif action == 'transfer':
            receiver_username = request.form['receiver_username']
            # 잔액 확인
            cursor.execute("SELECT balance FROM user WHERE id = ?", (session['user_id'],))
            balance = cursor.fetchone()['balance']
            if balance < amount:
                flash('잔액이 부족합니다.')
                return redirect(url_for('wallet'))
            
            # 수신자 확인
            cursor.execute("SELECT * FROM user WHERE username = ?", (receiver_username,))
            receiver = cursor.fetchone()
            if not receiver:
                flash('수신자를 찾을 수 없습니다.')
                return redirect(url_for('wallet'))
            
            # 송금 처리
            cursor.execute("""
                UPDATE user 
                SET balance = balance - ? 
                WHERE id = ?
            """, (amount, session['user_id']))
            
            cursor.execute("""
                UPDATE user 
                SET balance = balance + ? 
                WHERE id = ?
            """, (amount, receiver['id']))
            
            # 거래 내역 기록
            transaction_id = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO transactions (id, sender_id, receiver_id, amount, type)
                VALUES (?, ?, ?, ?, 'transfer')
            """, (transaction_id, session['user_id'], receiver['id'], amount))
            
            flash(f'{receiver_username}님에게 {amount}원이 송금되었습니다.')
        
        db.commit()
        return redirect(url_for('wallet'))
    
    # 현재 사용자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    
    # 거래 내역 조회
    cursor.execute("""
        SELECT t.*, 
               u1.username as sender_name,
               u2.username as receiver_name
        FROM transactions t
        JOIN user u1 ON t.sender_id = u1.id
        JOIN user u2 ON t.receiver_id = u2.id
        WHERE t.sender_id = ? OR t.receiver_id = ?
        ORDER BY t.created_at DESC
        LIMIT 10
    """, (session['user_id'], session['user_id']))
    transactions = cursor.fetchall()
    
    return render_template('wallet.html', user=user, transactions=transactions)

@app.route('/product/<product_id>/mark_sold', methods=['POST'])
@login_required
@check_banned
@seller_required
def mark_as_sold(product_id):
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("UPDATE product SET is_sold = 1 WHERE id = ?", (product_id,))
    db.commit()
    
    flash('상품이 거래 완료 처리되었습니다.')
    return redirect(url_for('my_products'))

@app.route('/product/<product_id>/mark_unsold', methods=['POST'])
@login_required
@check_banned
@seller_required
def mark_as_unsold(product_id):
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("UPDATE product SET is_sold = 0 WHERE id = ?", (product_id,))
    db.commit()
    
    flash('상품이 판매 중으로 변경되었습니다.')
    return redirect(url_for('my_products'))

if __name__ == '__main__':
    init_db()  # 데이터베이스 초기화
    socketio.run(app)

