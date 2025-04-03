from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from datetime import datetime
import pyodbc
import os
from decimal import Decimal
import pandas as pd
import openpyxl
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps  # 用于装饰器
app = Flask(__name__)

# 生产环境推荐配置
app.secret_key = 'f5c3a7e8d91b4e6a2c9f0b7d8e3a1f5f5c3a7e8d91b4e6a2c9f0b7d8e3a1f5'

# 数据库连接
def get_db():
    return pyodbc.connect(
        'DRIVER={ODBC Driver 17 for SQL Server};'
        'SERVER=localhost;'
        'DATABASE=PCT002;'
        'UID=sa;'
        'PWD=dell-110;'
    )


def generate_formatted_id():
    conn = get_db()
    cursor = conn.cursor()

    try:
        # 获取当前日期（格式：YYYYMMDD）
        today = datetime.now().strftime("%Y%m%d")

        # 查询当日已有配置数量
        cursor.execute("""
            SELECT MAX(daily_sequence) 
            FROM configurations 
            WHERE config_date = CONVERT(DATE, GETDATE())
        """)
        max_sequence = cursor.fetchone()[0] or 0

        # 生成新序列号
        new_sequence = max_sequence + 1

        # 组合成格式化ID
        formatted_id = f"{today}{new_sequence:03d}"  # 如20250316001

        return formatted_id, today, new_sequence
    finally:
        cursor.close()
        conn.close()


def authenticate_user(username, password):
    """验证用户凭据"""
    conn = None
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor()

        # 查询用户
        cursor.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()

        # 验证结果
        if user and check_password_hash(user.password_hash, password):
            return {
                'id': user.id,
                'username': user.username
            }
        return None

    except Exception as e:
        print(f"认证失败: {str(e)}")
        return None
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/test_session')
def test_session():
    session['test'] = 'session_works'
    return 'Session test passed! Check cookies.'

# 登录路由
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()

        # 基础验证
        if not username or not password:
            error = "用户名和密码不能为空"
        else:
            user = authenticate_user(username, password)
            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                return redirect(url_for('dashboard'))  # 重定向到 dashboard
            else:
                error = "用户名或密码错误"

    return render_template('login.html', error=error)


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


# 登录装饰器
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function

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

# 保存配置
@app.route('/save_config', methods=['POST'])
def save_config():
    data = request.json
    conn = get_db()
    cursor = conn.cursor()

    try:
        # 生成ID和日期信息
        formatted_id, config_date, daily_sequence = generate_formatted_id()

        # 插入配置
        cursor.execute("""
            INSERT INTO configurations 
            (formatted_id, config_date, daily_sequence, discount, total_price)
            OUTPUT INSERTED.config_id
            VALUES (?, ?, ?, ?, ?)
        """, (
            formatted_id,
            config_date,
            daily_sequence,
            Decimal(data['discount']),
            Decimal(data['total_price'])
        ))
        config_id = cursor.fetchval()

        # 插入配置项
        for item in data['items']:
            cursor.execute("""
                INSERT INTO config_items 
                (config_id, part_number, qty, unit_price_eur)
                VALUES (?, ?, ?, ?)
            """, (
                config_id,
                item['part_number'],
                item['qty'],
                Decimal(item['unit_price_eur'])
            ))
        conn.commit()

        return jsonify({
            'config_id': config_id,
            'formatted_id': formatted_id
        })
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# 主页面
@app.route('/m_select', methods=['GET', 'POST'])
def m_select():

    conn = get_db()
    if request.method == 'POST':

        # 获取表单数据
        part_numbers = request.form.getlist('part_number[]')
        quantities = request.form.getlist('qty[]')
        # discount = float(request.form.get('discount', 1.0))
        # 获取折扣并转换为Decimal
        discount_str = request.form.get('discount', '1.0')
        try:
            discount = Decimal(discount_str)
        except:
            discount = Decimal('1.0')  # 默认值

        results = []
        total_price = 0

        # 遍历每一行输入
        for pn, qty in zip(part_numbers, quantities):
            if pn and qty:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT UnitPrice_EUR, GreenPrice_CNY, SUC_CNY, UnitListPrice_CNY "
                    "FROM list WHERE CodeNo=?", pn
                )
                row = cursor.fetchone()
                if row:
                    qty = int(qty)

                    grp_sum = qty * Decimal(str(row.GreenPrice_CNY))  # 确保类型转换
                    total_cost = qty * Decimal(str(row.SUC_CNY))
                    total_price_cny = qty * Decimal(str(row.UnitListPrice_CNY))

                    margin = ((total_price_cny - total_cost) / total_price_cny * 100) if total_price_cny != 0 else 0
                    grp_index = (total_price_cny / grp_sum * 100) if grp_sum != 0 else 0

                    results.append({
                        'part_number': pn,
                        'unit_price_eur': row.UnitPrice_EUR,
                        'green_price_cny': row.GreenPrice_CNY,
                        'suc_cny': row.SUC_CNY,
                        'unit_list_price_cny': row.UnitListPrice_CNY,
                        'qty': qty,
                        'grp_sum': grp_sum,
                        'total_cost': total_cost,
                        'total_price_cny': total_price_cny,
                        'margin': round(margin, 2),
                        'grp_index': round(grp_index, 2),
                        'discounted_price': total_price_cny * discount
                    })
                    total_price += total_price_cny * discount

        return render_template('Mselect.html',
                               results=results,
                               total_price=total_price,
                               discount=discount)

    return render_template('Mselect.html')



@app.route('/config', defaults={'formatted_id': None})
@app.route('/config/<int:formatted_id>')
def view_config(formatted_id):
    conn = get_db()
    cursor = conn.cursor()
    per_page = 12  # 每页显示数量
    page = request.args.get('page', 1, type=int)

    try:
        if formatted_id:  # 存在ID时查询单个配置
            print(f"[Query] 正在查询配置: {formatted_id}")

            # 1. 查询配置头信息
            cursor.execute("""
                SELECT c.config_id, c.formatted_id, c.discount, c.total_price, c.created_at
                FROM configurations c
                WHERE c.formatted_id = ?
            """, (formatted_id,))
            config = cursor.fetchone()
            print("[DEBUG] Config:", config)  # 添加调试输出

            if not config:
                return "配置不存在", 404

            # 2. 查询配置项
            cursor.execute("""
                SELECT i.part_number, i.qty, i.unit_price_eur 
                FROM config_items i
                JOIN list l ON i.part_number = l.CodeNo
                WHERE i.config_id = ?
            """, (config.config_id,))

            items = cursor.fetchall()
            print("[DEBUG] Items:", items)  # 添加调试输出

            # 转换为字典格式
            config_dict = {
                'formatted_id': config.formatted_id,
                'discount': float(config.discount),
                'total_price': float(config.total_price),
                'created_at': config.created_at
            }
            items_list = [dict(zip([column[0] for column in cursor.description], row)) for row in items]

            return render_template('config_detail.html',
                                config=config_dict,
                                items=items)
        else:  # 无ID时查询所有配置
            print("[Query] 正在查询全部配置")
            # page = request.args.get('page', 1, type=int)
            # offset = (page - 1) * PER_PAGE

            # 计算总页数
            cursor.execute("SELECT COUNT(*) FROM configurations")
            total_items  = cursor.fetchone()[0]
            total_pages = (total_items  + per_page - 1) // per_page
            offset = (page - 1) * per_page

            limit = page * per_page

            cursor.execute("""
                    SELECT 
                        c.formatted_id, 
                        c.discount, 
                        c.total_price, 
                        CONVERT(varchar, c.created_at, 120) as created_at,  -- 明确转换为字符串
                        COUNT(i.item_id) as items_count
                    FROM configurations c
                    LEFT JOIN config_items i ON c.config_id = i.config_id
                    GROUP BY c.config_id, c.formatted_id, c.discount, c.total_price, c.created_at
                    ORDER BY c.created_at DESC
                    OFFSET ? ROWS FETCH NEXT ? ROWS ONLY
                """, (offset, per_page))

            configs = [dict(zip([column[0] for column in cursor.description], row))
                 for row in cursor.fetchall()] # 获取分页数据

            for row in cursor.fetchall():
                config = {
                    'formatted_id': row.formatted_id,
                    'discount': float(row.discount),
                    'total_price': float(row.total_price),
                    'created_at': row.created_at,  # 直接使用字符串
                    'items_count': row.items_count
                }
                configs.append(config)



            return render_template('config_list.html',
                               configs=configs,
                               current_page=page,
                               total_pages=total_pages,
                               total_items=total_items)

    except Exception as e:
        print("[ERROR]", str(e))  # 输出错误日志
        return f"服务器错误: {str(e)}", 500
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()


ALLOWED_EXTENSIONS = {'xlsx', 'xls'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    conn = None
    cursor = None
    if request.method == 'POST':

        try:
            # === 阶段1：基础验证 ===
            if 'file' not in request.files:
                return jsonify({'error': '未选择文件'}), 400

            file = request.files['file']
            if not allowed_file(file.filename):
                return jsonify({'error': '仅支持.xlsx/.xls文件'}), 400

            # === 阶段2：数据读取 ===
            df = pd.read_excel(file)
            required_cols = ['Chapter', 'ProductType', 'KDCode', 'CodeNo', 'UnitPrice_EUR', 'GreenPrice_CNY', 'SUC_CNY', 'UnitListPrice_CNY']
            if not all(col in df.columns for col in required_cols):
                return jsonify({'error': '缺少必要列'}), 400

            # === 阶段3：数据库操作 ===
            conn = get_db()  # 关键点：在验证通过后连接
            cursor = conn.cursor()

            insert_sql = """INSERT INTO list (
                                            Chapter, 
                                            ProductType, 
                                            KDCode, 
                                            CodeNo, 
                                            UnitPrice_EUR, 
                                            GreenPrice_CNY, 
                                            SUC_CNY, 
                                            UnitListPrice_CNY,
                                            UpDateTime
                                            ) 
            VALUES (?,?,?,?,?,?,?,?,GETDATE())"""
            for _, row in df.iterrows():
                # 构造参数元组（必须包含5个元素）
                params = (
                    str(row['Chapter']),
                    str(row['ProductType']),
                    str(row['KDCode']),
                    str(row['CodeNo']),
                    float(row['UnitPrice_EUR']),
                    float(row['GreenPrice_CNY']),
                    float(row['SUC_CNY']),
                    float(row['UnitListPrice_CNY']),
                    )

                # 调试打印
                print(f"[DEBUG] SQL: {insert_sql}")
                print(f"[DEBUG] Params: {params}")

                cursor.execute(insert_sql, params)  # 传递参数

            conn.commit()
            return jsonify({'success': f'成功插入{len(df)}条记录'}), 200

        except Exception as e:
            if conn:
                conn.rollback()
            return jsonify({'error': str(e)}), 500
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    return render_template('upload.html')



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


if __name__ == '__main__':
    app.run()