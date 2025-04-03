from flask import Flask, render_template, request, jsonify, redirect, url_for, session, g
from datetime import datetime
import pyodbc
import os
from decimal import Decimal
import pandas as pd
import openpyxl
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import logging

# 加载环境变量
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback-secret-key')

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 数据库配置
DATABASE_CONFIG = {
    'driver': os.getenv('DB_DRIVER', 'ODBC Driver 17 for SQL Server'),
    'server': os.getenv('DB_SERVER', 'localhost'),
    'database': os.getenv('DB_NAME', 'PCT002'),
    'user': os.getenv('DB_USER', 'sa'),
    'password': os.getenv('DB_PASSWORD', 'dell-110')
}


def get_db_connection():
    """获取数据库连接并存入g对象"""
    if 'db' not in g:
        conn_str = (
            f"DRIVER={{{DATABASE_CONFIG['driver']}}};"
            f"SERVER={DATABASE_CONFIG['server']};"
            f"DATABASE={DATABASE_CONFIG['database']};"
            f"UID={DATABASE_CONFIG['user']};"
            f"PWD={DATABASE_CONFIG['password']}"
        )
        g.db = pyodbc.connect(conn_str)
    return g.db


@app.teardown_appcontext
def close_db(error):
    """自动关闭数据库连接"""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def db_execute(query, params=(), commit=False):
    """执行数据库操作的公共方法"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(query, params)
        if commit:
            conn.commit()
        return cursor
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error: {str(e)}")
        raise


# 错误处理器
@app.errorhandler(404)
def page_not_found(e):
    # 记录404错误日志
    app.logger.warning(f'404 Not Found: {request.url}')
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    # 记录500错误日志
    app.logger.error(f'500 Internal Server Error: {str(e)}')
    return render_template('500.html', error=str(e)), 500


# 装饰器：登录要求
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


# 公共方法：生成配置ID
def generate_formatted_id():
    try:
        today = datetime.now().strftime("%Y%m%d")
        cursor = db_execute(
            """SELECT MAX(daily_sequence) 
            FROM configurations 
            WHERE config_date = CONVERT(DATE, GETDATE())"""
        )
        max_sequence = cursor.fetchone()[0] or 0
        new_sequence = max_sequence + 1
        return f"{today}{new_sequence:03d}", today, new_sequence
    except Exception as e:
        logger.error(f"Generate ID failed: {str(e)}")
        raise


# 用户认证相关路由
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            return render_template('login.html', error="用户名和密码不能为空")

        try:
            user = authenticate_user(username, password)
            if user:
                session.update({
                    'user_id': user['id'],
                    'username': user['username']
                })
                return redirect(url_for('dashboard'))
            return render_template('login.html', error="用户名或密码错误")
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return render_template('login.html', error="系统错误，请稍后再试")

    return render_template('login.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        confirm = request.form.get('confirm_password').strip()

        # 基础验证
        if not username or not password:
            error = "必填字段不能为空"
        elif len(username) < 4:
            error = "用户名至少4个字符"
        elif password != confirm:
            error = "两次密码输入不一致"
        else:
            try:
                # 检查用户名是否存在
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute("SELECT 1 FROM users WHERE username=?", (username,))
                if cursor.fetchone():
                    error = "用户名已存在"
                else:
                    # 创建用户
                    hashed_pw = generate_password_hash(password)
                    cursor.execute(
                        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                        (username, hashed_pw)
                    )
                    conn.commit()
                    return redirect(url_for('login'))
            except Exception as e:
                error = "注册失败，请稍后再试"
                print(f"注册错误: {str(e)}")
            finally:
                cursor.close()
                conn.close()

    return render_template('register.html', error=error)

# 登出路由
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# 新增API：搜索Part Number
@app.route('/search')
def search_part():
    conn = get_db()
    cursor = conn.cursor()

    try:
        search_term = request.args.get('term', '')
        cursor.execute(
            "SELECT CodeNo,KDCode FROM list WHERE CodeNo LIKE ?",
            (f'%{search_term}%',)
        )
        results = [{'code': row.CodeNo,'KDCode':row.KDCode} for row in cursor]
        return jsonify(results)
    finally:
        cursor.close()
        conn.close()

# 新增API：获取产品详细信息
@app.route('/get_part/<code>')
def get_part(code):
    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT UnitPrice_EUR, GreenPrice_CNY, SUC_CNY, UnitListPrice_CNY "
            "FROM list WHERE CodeNo=?",
            (code,)
        )
        row = cursor.fetchone()
        if row:
            return jsonify({
                'unit_price_eur': float(row.UnitPrice_EUR),
                'green_price_cny': float(row.GreenPrice_CNY),
                'suc_cny': float(row.SUC_CNY),
                'unit_list_price_cny': float(row.UnitListPrice_CNY)
            })
        return jsonify({'error': 'Not found'}), 404
    finally:
        cursor.close()
        conn.close()


@app.route('/test_session')
def test_session():
    session['test'] = 'session_works'
    return 'Session test passed! Check cookies.'


def authenticate_user(username, password):
    """用户认证逻辑"""
    try:
        cursor = db_execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        if user and check_password_hash(user.password_hash, password):
            return {'id': user.id, 'username': user.username}
        return None
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise


# 配置管理相关路由
@app.route('/save_config', methods=['POST'])
@login_required
def save_config():
    try:
        data = request.get_json()
        formatted_id, config_date, daily_sequence = generate_formatted_id()

        # 插入配置主表
        cursor = db_execute(
            """INSERT INTO configurations 
            (formatted_id, config_date, daily_sequence, discount, total_price)
            OUTPUT INSERTED.config_id
            VALUES (?, ?, ?, ?, ?)""",
            (formatted_id, config_date, daily_sequence,
             Decimal(data['discount']), Decimal(data['total_price'])),
            commit=True
        )
        config_id = cursor.fetchval()

        # 插入配置项
        for item in data['items']:
            db_execute(
                """INSERT INTO config_items 
                (config_id, part_number, qty, unit_price_eur)
                VALUES (?, ?, ?, ?)""",
                (config_id, item['part_number'], item['qty'],
                 Decimal(item['unit_price_eur'])),
                commit=True
            )

        return jsonify({
            'config_id': config_id,
            'formatted_id': formatted_id
        })
    except Exception as e:
        logger.error(f"Save config failed: {str(e)}")
        return jsonify({'error': '配置保存失败'}), 500


# 文件上传相关
ALLOWED_EXTENSIONS = {'xlsx', 'xls'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': '未选择文件'}), 400

        file = request.files['file']
        if not allowed_file(file.filename):
            return jsonify({'error': '仅支持.xlsx/.xls文件'}), 400

        df = pd.read_excel(file)
        required_cols = ['Chapter', 'ProductType', 'KDCode', 'CodeNo',
                         'UnitPrice_EUR', 'GreenPrice_CNY', 'SUC_CNY', 'UnitListPrice_CNY']

        if not all(col in df.columns for col in required_cols):
            return jsonify({'error': '缺少必要列'}), 400

        # 批量插入
        insert_sql = """INSERT INTO list (Chapter, ProductType, KDCode, CodeNo,
                        UnitPrice_EUR, GreenPrice_CNY, SUC_CNY, UnitListPrice_CNY)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)"""

        params = [tuple(row[col] for col in required_cols) for _, row in df.iterrows()]
        db_execute(insert_sql, params, commit=True)

        return jsonify({'success': f'成功插入{len(params)}条记录'}), 200
    except Exception as e:
        logger.error(f"Upload failed: {str(e)}")
        return jsonify({'error': '文件处理失败'}), 500


# 其他路由保持不变，但应添加@login_required装饰器
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/maintenance')
@login_required
def maintenance():
    # 获取产品基础数据
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM list")
    products = [dict(zip([column[0] for column in cursor.description], row))
               for row in cursor.fetchall()]
    return render_template('maintenance.html', products=products)

# ... 其他路由和功能保持类似结构，使用新的数据库操作方法 ...

if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', False))