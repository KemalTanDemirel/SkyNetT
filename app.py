from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, abort, make_response, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from flask_migrate import Migrate
from flask_apscheduler import APScheduler
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from datetime import datetime, timedelta, date
from zoneinfo import ZoneInfo
import os
from werkzeug.security import generate_password_hash, check_password_hash
import re
from werkzeug.utils import secure_filename
from collections import defaultdict
import time
import uuid
from models import db, User, Group, Message, DirectMessage, ForumThread, ForumPost, GroupJoinRequest, Notification, UserSession, Poll, PollOption, PollVote, Confession
from sqlalchemy import func
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///skynex.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/images/profiles'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Varsayılan site ayarları
app.config['MAINTENANCE_MODE'] = False
app.config['REGISTRATION_OPEN'] = True

# APScheduler Yapılandırması
app.config['SCHEDULER_API_ENABLED'] = True
scheduler = APScheduler()

migrate = Migrate(app, db)
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Email validation regex
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@(gmail\.com|hotmail\.com|protonmail\.com)$'

# Rate limiting dictionary {ip: {endpoint: [timestamps]}}
rate_limits = defaultdict(lambda: defaultdict(list))

# Global chat rate limiting
last_message_time = {}
RATE_LIMIT_SECONDS = 3

# Function to check rate limit (updated for list-based timestamps)
def check_rate_limit(ip, endpoint, max_attempts, window_seconds):
    current_time = time.time()
    key = f"{ip}:{endpoint}"

    # Remove timestamps older than the window
    # rate_limits[ip][endpoint] artık bir liste, bu yüzden filtreleme yapıyoruz.
    rate_limits[ip][endpoint] = [t for t in rate_limits[ip][endpoint] if current_time - t < window_seconds]

    # Add current attempt timestamp
    rate_limits[ip][endpoint].append(current_time)

    # Check if rate limit is exceeded (liste uzunluğu max_attempts'den büyükse aşılmıştır)
    return len(rate_limits[ip][endpoint]) <= max_attempts

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def welcome():
    # Ana sayfa yönlendirmesi. Eğer kullanıcı kimliği doğrulanmışsa (Flask-Login session cookie var),
    # before_request fonksiyonu geçerli bir UserSession tokenı olup olmadığını kontrol edecek.
    # Eğer geçerli bir UserSession varsa chat sayfasına yönlendirilecek, yoksa logout yapılıp gate'e.
    # Kimliği doğrulanmamışsa doğrudan gate sayfasına yönlendirilecek.
    if current_user.is_authenticated:
         return redirect(url_for('chat')) # Authenticated users go to chat, session check happens in before_request
    else:
        return redirect(url_for('gate')) # Unauthenticated users go to gate

@app.route('/logo')
def logo_redirect():
    if current_user.is_authenticated:
        # Check device token before redirecting to chat
        browser_device_token = request.cookies.get('device_token')
        if current_user.device_token and browser_device_token == current_user.device_token:
            return redirect(url_for('chat')) # Redirect to main chat
        else:
            logout_user()
            return redirect(url_for('gate'))

    return redirect(url_for('gate')) # Redirect to gate

@app.route('/check_session')
def check_session():
    return jsonify({'logged_in': current_user.is_authenticated})

# Form sınıfları
class LoginForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[DataRequired()])
    password = PasswordField('Şifre', validators=[DataRequired()])
    remember_me = BooleanField('Beni Hatırla')
    submit = SubmitField('Giriş Yap')

class RegistrationForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[
        DataRequired(),
        Length(min=3, max=20, message='Kullanıcı adı 3-20 karakter arasında olmalıdır.')
    ])
    email = StringField('E-posta', validators=[
        DataRequired(),
        Email(message='Geçerli bir e-posta adresi giriniz.')
    ])
    password = PasswordField('Şifre', validators=[
        DataRequired(),
        Length(min=6, message='Şifre en az 6 karakter olmalıdır.')
    ])
    password2 = PasswordField('Şifre Tekrar', validators=[
        DataRequired(),
        EqualTo('password', message='Şifreler eşleşmiyor.')
    ])
    submit = SubmitField('Kayıt Ol')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Bu kullanıcı adı zaten kullanılıyor.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Bu e-posta adresi zaten kayıtlı.')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))

    form = LoginForm()
    if form.validate_on_submit():
        print(f"[DEBUG] Login attempt for username: {form.username.data}")
        user = User.query.filter_by(username=form.username.data).first()
        
        if user:
            print(f"[DEBUG] User found in database")
            if check_password_hash(user.password_hash, form.password.data):
                print(f"[DEBUG] Password is correct")
                # Cihaz token kontrolü
                browser_device_token = request.cookies.get('device_token')
                print(f"[DEBUG] Browser device token: {browser_device_token}")
                print(f"[DEBUG] User device token: {user.device_token}")

                # --- EKSTRA GÜVENLİK: Cihazda başka kullanıcıya ait device_token varsa giriş engellensin ---
                if browser_device_token:
                    other_user = User.query.filter(User.device_token == browser_device_token, User.id != user.id).first()
                    if other_user:
                        print(f"[DEBUG] This device is already linked to another user: {other_user.username}")
                        flash('Bu cihaz başka bir kullanıcıya bağlı. Farklı bir kullanıcı ile giriş yapılamaz.', 'error')
                        return redirect(url_for('login'))
                # --- SON EKSTRA GÜVENLİK ---

                if user.device_token is None:
                    # İlk giriş - yeni cihaz token'ı oluştur
                    new_device_token = str(uuid.uuid4())
                    user.device_token = new_device_token
                    db.session.commit()
                    print(f"[DEBUG] Created new device token: {new_device_token}")
                    
                    # Giriş yap ve cookie'yi ayarla
                    login_user(user, remember=form.remember_me.data)
                    
                    # Session token oluştur
                    session_token = str(uuid.uuid4())
                    user_session = UserSession(
                        user_id=user.id,
                        session_token=session_token,
                        is_active=True
                    )
                    db.session.add(user_session)
                    db.session.commit()
                    
                    response = make_response(redirect(url_for('chat')))
                    response.set_cookie('device_token', new_device_token, max_age=60*60*24*365)  # 1 yıl
                    response.set_cookie('session_token', session_token, max_age=60*60*24*7)  # 7 gün
                    print(f"[DEBUG] Login successful, redirecting to chat")
                    return response
                elif browser_device_token == user.device_token:
                    # Aynı cihazdan giriş - normal giriş yap
                    login_user(user, remember=form.remember_me.data)
                    
                    # Session token oluştur
                    session_token = str(uuid.uuid4())
                    user_session = UserSession(
                        user_id=user.id,
                        session_token=session_token,
                        is_active=True
                    )
                    db.session.add(user_session)
                    db.session.commit()
                    
                    response = make_response(redirect(url_for('chat')))
                    response.set_cookie('session_token', session_token, max_age=60*60*24*7)  # 7 gün
                    print(f"[DEBUG] Login successful from same device")
                    return response
                else:
                    # Farklı cihazdan giriş denemesi
                    print(f"[DEBUG] Login attempt from different device")
                    flash('Bu hesap başka bir cihaza bağlı. Sadece ilk giriş yapılan cihazdan erişilebilir.', 'error')
                    return redirect(url_for('login'))
            else:
                print(f"[DEBUG] Password is incorrect")
                flash('Geçersiz kullanıcı adı veya şifre', 'error')
                return redirect(url_for('login'))
        else:
            print(f"[DEBUG] User not found in database")
            flash('Geçersiz kullanıcı adı veya şifre', 'error')
            return redirect(url_for('login'))

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    browser_session_token = request.cookies.get('session_token')
    if browser_session_token:
        user_session = UserSession.query.filter_by(user_id=current_user.id, session_token=browser_session_token, is_active=True).first()
        if user_session:
            user_session.is_active = False
            db.session.commit()
            print(f"[DEBUG logout] Marked session {browser_session_token} as inactive for user {current_user.username}.")

    logout_user()
    response = make_response(redirect(url_for('gate') if app.config.get('SITE_PASSWORD_REQUIRED', False) else url_for('login')))
    # Sadece session token'ı sil, device token'ı koru
    response.set_cookie('session_token', '', expires=0, httponly=True, secure=app.config['SESSION_COOKIE_SECURE'], samesite='Lax', path='/')
    flash('Başarıyla çıkış yapıldı.', 'success')
    return response

# Sesion Kontrolü ve Tek Oturum
@app.before_request
def check_user_session():
    # Site şifresi kontrolü, eğer 'gate' rotasında değilsek ve site şifresi gerekliyse.
    allowed_endpoints = ['gate', 'static', 'login', 'logout', 'check_session', 'banned']

    site_password_required = app.config.get('SITE_PASSWORD_REQUIRED', False)
    if site_password_required and request.endpoint not in allowed_endpoints:
        if 'site_password_ok' not in session:
            return redirect(url_for('gate'))

    # Kimliği doğrulanmış kullanıcılar için yasaklama kontrolü
    if current_user.is_authenticated and request.endpoint not in allowed_endpoints:
        if current_user.is_banned:
            if current_user.banned_until and current_user.banned_until > datetime.utcnow():
                return redirect(url_for('banned'))
            else:
                # Yasaklama süresi dolmuşsa yasağı kaldır
                current_user.is_banned = False
                current_user.banned_until = None
                db.session.commit()

    # Kimliği doğrulanmış kullanıcılar için oturum token kontrolü
    # Eğer kullanıcı yeni login olduysa (session içinde flag varsa) bu kontrolü atla.
    # Sadece kimliği doğrulanmış ve muaf olmayan rotalar için kontrol yap
    if current_user.is_authenticated and request.endpoint not in allowed_endpoints:
        # Eğer kullanıcı yeni login olduysa bu ilk kontrollü istektir, flagı kaldır ve kontrolü atla.
        if session.pop('just_logged_in', None):
            print(f"[DEBUG before_request] Skipping session token check for new login: {current_user.username}")
            # Yeni login sonrası ilk isteğin devam etmesine izin ver
            return

        # Eğer yeni login değilse, normal oturum token kontrolünü yap.
        browser_session_token = request.cookies.get('session_token')

        print(f"[DEBUG before_request] User {current_user.username} is authenticated. Checking session token.")
        print(f"[DEBUG before_request] Browser session token: {browser_session_token}")

        # Oturumu hem token hem de is_active=True ile kontrol et
        user_session = UserSession.query.filter_by(user_id=current_user.id, session_token=browser_session_token, is_active=True).first()

        print(f"[DEBUG before_request] User session found in DB (active): {user_session is not None}")

        if not user_session:
            # Aktif oturum bulunamadı, kullanıcıyı logout et ve çerezi temizle.
            print(f"[DEBUG before_request] Invalid or missing active session token for user {current_user.username}. Logging out and clearing cookie.")
            logout_user()
            response = make_response(redirect(url_for('gate') if 'site_password_ok' not in session else url_for('login')))
            response.set_cookie('session_token', '', expires=0, httponly=True, secure=app.config['SESSION_COOKIE_SECURE'], samesite='Lax', path='/')
            return response # İsteği burada kes ve yönlendirmeyi yap

        else:
            # Oturum geçerli, son erişim zamanını güncelle
            user_session.last_accessed = datetime.utcnow()
            db.session.commit()
            # İstek işlemeye devam edecek.

    # Eğer kullanıcı kimliği doğrulanmamışsa veya kontrol atlandıysa, isteğin devam etmesine izin ver.
    pass

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user
    if request.method == 'POST':
        # Handle profile updates
        user.username = request.form.get('username', user.username)
        user.description = request.form.get('description', user.description)
        user.theme = request.form.get('theme', user.theme)
        user.anonymous_profile = request.form.get('anonymous_profile', user.anonymous_profile)
        user.message_notifications = 'message_notifications' in request.form

        # Handle profile image upload
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and allowed_file(file.filename):
                filename = secure_filename(f'{user.id}_{file.filename}')
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                # Save the new file
                file.save(filepath)
                
                # Delete old profile image if it exists and is not the default
                if user.profile_image and user.profile_image != 'default.png':
                    old_filepath = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_image)
                    if os.path.exists(old_filepath):
                        os.remove(old_filepath)

                # Update profile_image in DB with the filename
                user.profile_image = filename
                # Also update profile_image_url for easier access in templates/JS
                user.profile_image_url = url_for('static', filename=f'images/profiles/{filename}')


        try:
            db.session.commit()
            flash('Profiliniz güncellendi.', 'success')
            return redirect(url_for('profile'))
        except Exception as e:
            db.session.rollback()
            flash(f'Profil güncellenirken bir hata oluştu: {str(e)}', 'danger')

    # Ensure profile_image_url is set correctly when rendering the page if only profile_image exists
    if user.profile_image and not user.profile_image_url:
         user.profile_image_url = url_for('static', filename=f'images/profiles/{user.profile_image}')
    elif not user.profile_image: # Handle case where profile_image is None or empty
         user.profile_image_url = url_for('static', filename='images/default.png')


    return render_template('profile.html', user=user)

# İzin verilen dosya uzantılarını kontrol et
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Forum Rotaları
@app.route('/forum')
@login_required
def forum():
    # En son forum başlıklarını çek
    threads = ForumThread.query.order_by(ForumThread.timestamp.desc()).all()
    # Her başlığın yazarını yükle
    for thread in threads:
        thread.author = User.query.get(thread.user_id)
    return render_template('forum.html', threads=threads)

@app.route('/create_forum', methods=['GET', 'POST'])
@login_required
def create_forum():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        # Fotoğraf yükleme işlevi buraya eklenecek

        if not title or not content:
            flash('Başlık ve içerik boş bırakılamaz.', 'danger')
            return redirect(url_for('create_forum'))

        new_thread = ForumThread(
            title=title,
            content=content,
            user_id=current_user.id
        )
        db.session.add(new_thread)
        db.session.commit()
        flash('Forum konusu başarıyla oluşturuldu!', 'success')
        return redirect(url_for('forum'))

    return render_template('create_forum.html')

@app.route('/forum/<int:id>')
@login_required
def view_forum(id):
    thread = ForumThread.query.get_or_404(id)
    # Get the author of the thread
    author = User.query.get(thread.user_id)
    # Get all posts for this thread, ordered by timestamp
    posts = ForumPost.query.filter_by(thread_id=id).order_by(ForumPost.timestamp.asc()).all()
    # Get authors for all posts
    for post in posts:
        post.author = User.query.get(post.user_id)
    
    return render_template('view_forum.html', 
                         thread=thread, 
                         author=author, 
                         posts=posts)

@app.route('/forum/<int:id>/reply', methods=['POST'])
@login_required
def reply_to_forum(id):
    thread = ForumThread.query.get_or_404(id)
    if thread.is_locked:
        flash('This thread is locked. You cannot reply.', 'danger')
        return redirect(url_for('view_forum', id=id))
        
    content = request.form.get('content')
    if not content:
        flash('Reply content cannot be empty.', 'danger')
        return redirect(url_for('view_forum', id=id))
        
    new_post = ForumPost(
        content=content,
        user_id=current_user.id,
        thread_id=id
    )
    db.session.add(new_post)
    db.session.commit()
    
    flash('Your reply has been posted successfully!', 'success')
    return redirect(url_for('view_forum', id=id))

@app.route('/forum/<int:id>/lock', methods=['POST'])
@login_required
def lock_forum(id):
    thread = ForumThread.query.get_or_404(id)
    # Only allow thread author or admin to lock the thread
    if current_user.id != thread.user_id and current_user.role != 'admin':
        flash('You do not have permission to lock this thread.', 'danger')
        return redirect(url_for('view_forum', id=id))
        
    thread.is_locked = not thread.is_locked  # Toggle lock status
    db.session.commit()
    
    status = 'locked' if thread.is_locked else 'unlocked'
    flash(f'Thread has been {status}.', 'success')
    return redirect(url_for('view_forum', id=id))

# Socket.IO events
@socketio.on('connect')
def handle_connect(auth=None):
    global system_messages
    if current_user.is_authenticated:
        print(f"Kullanıcı bağlandı: {current_user.username}")
        join_room('global')
        user_join_msg = {
            'id': None,
            'content': f'"{current_user.username}" Çevrimiçi',
            'timestamp': datetime.now(ZoneInfo('Europe/Istanbul')).strftime('%d.%m.%Y %H:%M'),
            'room': 'global',
            'user_id': None,
            'username': 'SYSTEM',
            'profile_image_url': '/static/images/default.png',
            'is_anonymous': False,
            'role': 'SYSTEM',
            'is_system': True,
            'system_type': 'connect',
            'system_username': current_user.username
        }
        system_messages.append(user_join_msg)
        if len(system_messages) > 100:
            system_messages.pop(0)
        emit('new_message', user_join_msg, room='global')
        emit('connection_status', {'status': 'connected', 'username': current_user.username})

@socketio.on('join_room')
def handle_join_room(data):
    if current_user.is_authenticated:
        room = data.get('room')
        if room.startswith('group_'):
            # Grup mesajları için özel işlem
            group_id = int(room.split('_')[1])
            group = Group.query.get(group_id)
            if group and group in current_user.groups:
                join_room(room)
                emit('room_changed', {'room': room}, room=room)
        elif room == 'global': # Only allow joining 'global' if not a group room
            join_room(room)
            emit('room_changed', {'room': room}, room=room)

@socketio.on('send_message')
def handle_message(data):
    if not current_user.is_authenticated:
        print("Oturum açılmamış kullanıcı mesaj göndermeye çalıştı")
        # Use the callback to send an error response back to the client
        return False, 'Oturum açmanız gerekiyor.'

    print(f"\nMesaj gönderme denemesi - Kullanıcı: {current_user.username}")
    print(f"Kullanıcı durumu - Yasaklı: {current_user.is_banned}, Susturulmuş: {current_user.is_muted}")

    try:
        # Kullanıcının yasaklı olup olmadığını kontrol et
        if current_user.is_banned:
            if current_user.banned_until and current_user.banned_until > datetime.utcnow():
                print(f"Kullanıcı yasaklı - Bitiş: {current_user.banned_until}")
                return False, f'Hesabınız {current_user.banned_until.strftime("%d.%m.%Y %H:%M")} tarihine kadar yasaklanmıştır.'
            else:
                print("Yasak süresi dolmuş, yasak kaldırılıyor")
                current_user.is_banned = False
                current_user.banned_until = None
                db.session.commit()

        # Kullanıcının susturulmuş olup olmadığını kontrol et
        if current_user.is_muted:
            if current_user.muted_until and current_user.muted_until > datetime.utcnow():
                print(f"Kullanıcı susturulmuş - Bitiş: {current_user.muted_until}")
                return False, f'Hesabınız {current_user.muted_until.strftime("%d.%m.%Y %H:%M")} tarihine kadar susturulmuştur.'
            else:
                print("Susturma süresi dolmuş, susturma kaldırılıyor")
                current_user.is_muted = False
                current_user.muted_until = None
                db.session.commit()

        room = data.get('room')
        content = data.get('content', '').strip()

        print(f"Mesaj içeriği: {content}")
        print(f"Hedef oda: {room}")

        if not content:
            print("Boş mesaj içeriği")
            return False, 'Mesaj içeriği boş olamaz.'

        if not room or (not room.startswith('group_') and room != 'global'): # Only allow 'global' or group rooms
            print(f"Geçersiz veya yetkisiz oda: {room}")
            return False, 'Geçersiz veya yetkisiz oda.'

        # Rate limiting for global chat
        if room == 'global':
            user_id = current_user.id
            current_time = time.time()
            if user_id in last_message_time and current_time - last_message_time[user_id] < RATE_LIMIT_SECONDS:
                remaining_time = RATE_LIMIT_SECONDS - (current_time - last_message_time[user_id])
                print(f"Rate limit engaged for user {current_user.username}. Remaining time: {remaining_time:.2f}s")
                return False, f'Çok hızlı mesaj gönderiyorsunuz! Lütfen {remaining_time:.1f} saniye bekleyin.'
            last_message_time[user_id] = current_time

        # Mesaj gönderme işlemleri...
        if room == 'global':
            print("Global mesaj gönderiliyor (Main Chat)")
            message = Message(
                content=content,
                user_id=current_user.id,
                room=room,
                timestamp=datetime.now(ZoneInfo('Europe/Istanbul'))
            )
            db.session.add(message)
            db.session.commit()

            message_data = {
                'id': message.id,
                'content': content,
                'timestamp': message.timestamp.astimezone(ZoneInfo('Europe/Istanbul')).strftime('%d.%m.%Y %H:%M'),
                'room': room,
                'user_id': current_user.id,
                'username': current_user.username,
                'profile_image_url': current_user.profile_image_url or url_for('static', filename='images/default.png'),
                'is_anonymous': False,
                'role': current_user.role
            }
            emit('new_message', message_data, room=room)
            print(f"Global mesaj başarıyla gönderildi: {current_user.username} -> {content}")
            return True, 'Mesaj başarıyla gönderildi' # Indicate success

        elif room.startswith('group_'):
            group_id = int(room.split('_')[1])
            group = Group.query.get(group_id)
            if not group:
                print(f"Grup bulunamadı: {group_id}")
                return False, 'Grup bulunamadı.'
            if group not in current_user.groups:
                print(f"Kullanıcı grupta değil: {current_user.username} -> {group.name}")
                return False, 'Bu grupta mesaj gönderme yetkiniz yok.'

            print(f"Grup mesajı gönderiliyor: {group.name}")
            message = Message(
                content=content,
                user_id=current_user.id,
                room=room,
                timestamp=datetime.now(ZoneInfo('Europe/Istanbul'))
            )
            db.session.add(message)
            db.session.commit()

            message_data = {
                'id': message.id,
                'content': content,
                'timestamp': message.timestamp.astimezone(ZoneInfo('Europe/Istanbul')).strftime('%d.%m.%Y %H:%M'),
                'room': room,
                'user_id': current_user.id,
                'username': current_user.username,
                'profile_image_url': current_user.profile_image_url or url_for('static', filename='images/default.png'),
                'is_anonymous': False,
                'role': current_user.role
            }
            emit('new_message', message_data, room=room)
            print(f"Grup mesajı başarıyla gönderildi: {current_user.username} -> {group.name} -> {content}")
            return True, 'Mesaj başarıyla gönderildi' # Indicate success

    except Exception as e:
        db.session.rollback()
        print(f"Mesaj gönderme hatası: {str(e)}")
        print(f"Hata detayı: {type(e).__name__}")
        # Use the callback to send an error response back to the client
        return False, f'Mesaj gönderilirken bir hata oluştu: {str(e)}'

@app.route('/messages/<room>')
@login_required
def load_room_messages(room):
    try:
        if room == 'anonymous':
            messages = Message.query.filter_by(room=room).order_by(Message.timestamp.desc()).limit(50).all()
            messages_data = []
            
            for message in reversed(messages):  # Mesajları kronolojik sıraya çevir
                user = User.query.get(message.user_id)
                if user:
                    profile_map = {
                        'standart': 'standart.png',
                        'giyuu': 'giyuu.png',
                        'standartkiz': 'standartkiz.png',
                    }
                    profile_file = profile_map.get(user.anonymous_profile, 'standart.png')
                    
                    message_data = {
                        'id': message.id,
                        'content': message.content,
                        'timestamp': message.timestamp.astimezone(ZoneInfo('Europe/Istanbul')).strftime('%d.%m.%Y %H:%M'),
                        'room': room,
                        'user_id': message.user_id,
                        'username': 'Anonim',
                        'profile_image_url': url_for('static', filename=f'images/{profile_file}'),
                        'is_anonymous': True
                    }
                    messages_data.append(message_data)
            
            print(f"Anonim mesajlar yüklendi: {len(messages_data)} mesaj")  # Debug için log
            return jsonify(messages_data)
            
        elif room == 'global':
            global system_messages
            messages = Message.query.filter_by(room=room).order_by(Message.timestamp.desc()).limit(50).all()
            messages_data = []
            for message in reversed(messages):  # Mesajları kronolojik sıraya çevir
                user = User.query.get(message.user_id)
                if user:
                    message_data = {
                        'id': message.id,
                        'content': message.content,
                        'timestamp': message.timestamp.astimezone(ZoneInfo('Europe/Istanbul')).strftime('%d.%m.%Y %H:%M'),
                        'room': room,
                        'user_id': message.user_id,
                        'username': user.username,
                        'profile_image_url': user.profile_image_url or url_for('static', filename='images/default.png'),
                        'is_anonymous': False
                    }
                    messages_data.append(message_data)
            # Son 20 sistem mesajını da ekle (connect/disconnect)
            if system_messages:
                messages_data += list(system_messages[-20:])
            print(f"Global mesajlar yüklendi: {len(messages_data)} mesaj")  # Debug için log
            return jsonify(messages_data)
            
        elif room.startswith('group_'):
            # Grup mesajları için mevcut kod aynen kalacak
            group_id = int(room.split('_')[1])
            group = Group.query.get(group_id)
            if not group or group not in current_user.groups:
                return jsonify({'error': 'Bu gruba erişim yetkiniz yok.'}), 403
                
            messages = Message.query.filter_by(room=room).order_by(Message.timestamp.desc()).limit(50).all()
            messages_data = []
            
            for message in reversed(messages):  # Mesajları kronolojik sıraya çevir
                user = User.query.get(message.user_id)
                if user:
                    message_data = {
                        'id': message.id,
                        'content': message.content,
                        'timestamp': message.timestamp.astimezone(ZoneInfo('Europe/Istanbul')).strftime('%d.%m.%Y %H:%M'),
                        'room': room,
                        'user_id': message.user_id,
                        'username': user.username,
                        'profile_image_url': user.profile_image_url or url_for('static', filename='images/default.png'),
                        'is_anonymous': False
                    }
                    messages_data.append(message_data)
            
            print(f"Grup mesajları yüklendi: {len(messages_data)} mesaj")  # Debug için log
            return jsonify(messages_data)
            
        return jsonify({'error': 'Geçersiz oda.'}), 400
        
    except Exception as e:
        print(f"Mesaj yükleme hatası: {str(e)}")  # Debug için log
        return jsonify({'error': 'Mesajlar yüklenirken bir hata oluştu.'}), 500

# Periyodik olarak mesajları silme fonksiyonu
def delete_old_messages():
    with app.app_context():
        one_minute_ago = datetime.utcnow() - timedelta(minutes=1)
        messages_to_delete = Message.query.filter(Message.timestamp < one_minute_ago).all()
        affected_rooms = set(m.room for m in messages_to_delete)
        for message in messages_to_delete:
            db.session.delete(message)
        db.session.commit()
        print(f'{len(messages_to_delete)} adet eski mesaj silindi.')
        # Her odadaki tüm istemcilere mesajları temizle eventi gönder
        for room in affected_rooms:
            socketio.emit('clear_messages', room=room)

# Scheduler'ı başlat
scheduler.init_app(app)
scheduler.add_job(id='delete_old_messages', 
                 func=delete_old_messages, 
                 trigger='interval', 
                 minutes=1)
scheduler.start()

def create_admin_user():
    with app.app_context():
        admin_user = User.query.filter_by(username='NEXUS').first()
        if not admin_user:
            admin_user = User(
                username='NEXUS',
                email='admin@skynex.com',
                role='admin'
            )
            admin_user.password_hash = generate_password_hash('SKYNEX')
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user 'NEXUS' created successfully!")

def create_predefined_users():
    with app.app_context():
        user = User.query.filter_by(username='Earle').first()
        if not user:
            user = User(
                username='Earle',
                role='Kullanıcı'
            )
            user.password_hash = generate_password_hash('yH5^rG8#sF2@kC7%')
            db.session.add(user)
            db.session.commit()
            print("Predefined user 'Earle' created successfully!")

# Chat routes
@app.route('/chat', defaults={'group_id': None})
@app.route('/chat/<int:group_id>')
@login_required
def chat(group_id):
    if group_id:
        group = Group.query.get(group_id)
        if not group or group not in current_user.groups:
             # Optionally flash a message or redirect to groups if not a member
             flash('Bu gruba erişim yetkiniz yok.', 'danger')
             return redirect(url_for('groups'))
        # Pass group_id to the template to signal it's a group chat
        return render_template('chat.html', is_anonymous=False, group_id=group_id, group_name=group.name)
    # If no group_id, render the default chat (global)
    return render_template('chat.html', is_anonymous=False, group_id=None, group_name='Main Chat')

# Rol bazlı yetkilendirme fonksiyonları
def is_nexus(user):
    return user.role == 'NEXUS'

def is_super_admin(user):
    return user.role in ['admin', 'NEXUS', 'RYDER', 'COBRA', 'DİABLO']

def is_helper_admin(user):
    return user.role == 'helper_admin'

def can_manage_users(user):
    return is_super_admin(user) or is_helper_admin(user)

def can_manage_groups(user):
    return is_super_admin(user)

def can_manage_admins(user):
    return is_nexus(user) or is_super_admin(user)

def can_change_role(user, target_role):
    if is_nexus(user):
        return True  # NEXUS tüm rolleri değiştirebilir
    elif is_super_admin(user):
        # Diğer süper adminler NEXUS rolünü atayamaz ve diğer adminlere işlem yapamaz
        return target_role != 'NEXUS'
    return False

# Admin panel route'unu güncelle
@app.route('/admin')
@login_required
def admin_panel():
    if not can_manage_users(current_user):
        flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
        return redirect(url_for('home'))
    users = User.query.all()
    groups = Group.query.all()
    return render_template('admin_panel.html', users=users, groups=groups)

# Admin user action route'unu güncelle
@app.route('/admin/user/<int:user_id>', methods=['POST'])
@login_required
def admin_user_action(user_id):
    if not can_manage_users(current_user):
        return jsonify({'error': 'Yetkisiz erişim'}), 403
    
    # Admin kendine işlem yapamaz (NEXUS hariç)
    if user_id == current_user.id and not is_nexus(current_user):
        return jsonify({'error': 'Kendinize işlem yapamazsınız'}), 403
    
    action = request.form.get('action')
    duration = request.form.get('duration')
    new_role = request.form.get('role')
    
    user = User.query.get_or_404(user_id)
    
    # NEXUS hariç diğer adminler adminlere işlem yapamaz
    if not is_nexus(current_user) and is_super_admin(user):
        return jsonify({'error': 'Bu kullanıcıya işlem yapamazsınız'}), 403
    
    # Yardımcı adminler sadece normal kullanıcılara işlem yapabilir
    if is_helper_admin(current_user) and user.role != 'user':
        return jsonify({'error': 'Yardımcı adminler sadece normal kullanıcılara işlem yapabilir'}), 403
    
    try:
        if action == 'change_role' and new_role:
            # NEXUS için tüm kısıtlamaları kaldır
            if not is_nexus(current_user):
                if not can_change_role(current_user, new_role):
                    return jsonify({'error': 'Bu rolü değiştirme yetkiniz yok'}), 403
            if new_role not in ['user', 'admin', 'NEXUS', 'RYDER', 'COBRA', 'DİABLO', 'helper_admin']:
                return jsonify({'error': 'Geçersiz rol'}), 400
            user.role = new_role
            message = f'{user.username} kullanıcısının rolü {new_role} olarak değiştirildi.'
            
        elif action == 'ban':
            if duration:
                user.banned_until = datetime.utcnow() + timedelta(days=int(duration))
            user.is_banned = True
            message = f'{user.username} kullanıcısı {duration if duration else "süresiz"} olarak yasaklandı.'
            
        elif action == 'unban':
            user.is_banned = False
            user.banned_until = None
            message = f'{user.username} kullanıcısının yasağı kaldırıldı.'
            
        elif action == 'mute':
            if duration:
                user.muted_until = datetime.utcnow() + timedelta(days=int(duration))
            user.is_muted = True
            message = f'{user.username} kullanıcısı {duration if duration else "süresiz"} olarak susturuldu.'
            
        elif action == 'unmute':
            user.is_muted = False
            user.muted_until = None
            message = f'{user.username} kullanıcısının susturması kaldırıldı.'
            
        elif action == 'grant_group_creation':
            if not can_manage_groups(current_user):
                return jsonify({'error': 'Grup yetkisi verme yetkiniz yok'}), 403
            user.can_create_groups = True
            message = f'{user.username} kullanıcısına grup oluşturma yetkisi verildi.'
            
        elif action == 'revoke_group_creation':
            if not can_manage_groups(current_user):
                return jsonify({'error': 'Grup yetkisi alma yetkiniz yok'}), 403
            user.can_create_groups = False
            message = f'{user.username} kullanıcısının grup oluşturma yetkisi alındı.'
            
        else:
            return jsonify({'error': 'Geçersiz işlem'}), 400
        
        db.session.commit()
        return jsonify({'success': True, 'message': message})
        
    except Exception as e:
        db.session.rollback()
        print(f"Admin işlem hatası: {str(e)}")
        return jsonify({'error': f'İşlem sırasında bir hata oluştu: {str(e)}'}), 500

@app.route('/admin/group/<int:group_id>/add_user', methods=['POST'])
@login_required
def admin_add_to_group(group_id):
    if not is_super_admin(current_user):
        return jsonify({'error': 'Yetkisiz erişim'}), 403
    
    user_id = request.form.get('user_id')
    if not user_id:
        return jsonify({'error': 'Kullanıcı ID gerekli'}), 400
    
    try:
        group = Group.query.get_or_404(group_id)
        user = User.query.get_or_404(user_id)
        
        # Kullanıcı zaten grupta mı kontrol et
        existing_member = UserGroups.query.filter_by(user_id=user.id, group_id=group.id).first()
        if existing_member:
            return jsonify({'success': False, 'message': 'Kullanıcı zaten grupta.'})
        
        # Yeni üye ekle
        new_member = UserGroups(user_id=user.id, group_id=group.id)
        db.session.add(new_member)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'{user.username} gruba eklendi.'})
    except Exception as e:
        db.session.rollback()
        print(f"Grup üyesi ekleme hatası: {str(e)}")
        return jsonify({'error': 'Kullanıcı gruba eklenirken bir hata oluştu'}), 500

@app.route('/admin/group/<int:group_id>/remove_user', methods=['POST'])
@login_required
def admin_remove_from_group(group_id):
    if not is_super_admin(current_user):
        return jsonify({'error': 'Yetkisiz erişim'}), 403
    
    user_id = request.form.get('user_id')
    if not user_id:
        return jsonify({'error': 'Kullanıcı ID gerekli'}), 400
    
    try:
        group = Group.query.get_or_404(group_id)
        user = User.query.get_or_404(user_id)
        
        # Kullanıcı grupta mı kontrol et
        member = UserGroups.query.filter_by(user_id=user.id, group_id=group.id).first()
        if not member:
            return jsonify({'success': False, 'message': 'Kullanıcı grupta değil.'})
        
        # Üyeyi gruptan çıkar
        db.session.delete(member)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'{user.username} gruptan çıkarıldı.'})
    except Exception as e:
        db.session.rollback()
        print(f"Grup üyesi çıkarma hatası: {str(e)}")
        return jsonify({'error': 'Kullanıcı gruptan çıkarılırken bir hata oluştu'}), 500

@app.route('/admin/group/<int:group_id>/members')
@login_required
def group_members(group_id):
    try:
        group = Group.query.get_or_404(group_id)
        
        # Kullanıcının grup yöneticisi veya süper admin olup olmadığını kontrol et
        is_admin = any(member.user_id == current_user.id and member.is_admin for member in group.members)
        if not is_admin and not is_super_admin(current_user):
            return jsonify({'success': False, 'error': 'Bu işlem için yetkiniz yok'})
            
        members = []
        for member in group.members:
            user = User.query.get(member.user_id)
            if user:
                members.append({
                    'id': user.id,
                    'username': user.username,
                    'is_admin': member.is_admin,
                    'joined_at': member.joined_at.strftime('%d.%m.%Y %H:%M')
                })
                
        return jsonify({
            'success': True,
            'group_name': group.name,
            'members': members
        })
        
    except Exception as e:
        print(f"Grup üyeleri listeleme hatası: {str(e)}")
        return jsonify({'success': False, 'error': 'Grup üyeleri listelenirken bir hata oluştu'})

@app.route('/admin/group/<int:group_id>/member/<int:user_id>/make_admin', methods=['POST'])
@login_required
def make_group_admin(group_id, user_id):
    group = Group.query.get_or_404(group_id)
    
    # Specific check for SKYNEX group: only NEXUS can manage members
    if group.name == 'SKYNEX':
        if not is_nexus(current_user):
            return jsonify({'success': False, 'error': 'Bu grubun üyelerini yönetme yetkiniz yok'}), 403
    else:
        # For other groups, check if current user is admin
        is_admin = UserGroups.query.filter_by(
            user_id=current_user.id,
            group_id=group_id,
            is_admin=True
        ).first()
        if not is_admin:
            return jsonify({'success': False, 'error': 'Bu grubun üyelerini yönetme yetkiniz yok'}), 403
    
    # Get target user's group membership
    user_group = UserGroups.query.filter_by(
        user_id=user_id,
        group_id=group_id
    ).first()
    
    if not user_group:
        return jsonify({'success': False, 'error': 'Kullanıcı bu grubun üyesi değil'}), 400
    
    if user_group.is_admin:
        return jsonify({'success': False, 'error': 'Kullanıcı zaten admin'}), 400
    
    user_group.is_admin = True
    
    try:
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/group/<int:group_id>/member/<int:user_id>/remove_admin', methods=['POST'])
@login_required
def remove_group_admin(group_id, user_id):
    group = Group.query.get_or_404(group_id)
    
    # Specific check for SKYNEX group: only NEXUS can manage members
    if group.name == 'SKYNEX':
        if not is_nexus(current_user):
            return jsonify({'success': False, 'error': 'Bu grubun üyelerini yönetme yetkiniz yok'}), 403
    else:
        # For other groups, check if current user is admin
        is_admin = UserGroups.query.filter_by(
            user_id=current_user.id,
            group_id=group_id,
            is_admin=True
        ).first()
        if not is_admin:
            return jsonify({'success': False, 'error': 'Bu grubun üyelerini yönetme yetkiniz yok'}), 403
    
    # Get target user's group membership
    user_group = UserGroups.query.filter_by(
        user_id=user_id,
        group_id=group_id
    ).first()
    
    if not user_group:
        return jsonify({'success': False, 'error': 'Kullanıcı bu grubun üyesi değil'}), 400
    
    if not user_group.is_admin:
        return jsonify({'success': False, 'error': 'Kullanıcı zaten admin değil'}), 400
    
    # Don't allow removing the last admin (especially for SKYNEX if NEXUS is the only admin)
    admin_count = UserGroups.query.filter_by(group_id=group_id, is_admin=True).count()
    if admin_count <= 1 and user_group.is_admin:
        return jsonify({'success': False, 'error': 'Grupta en az bir admin olmalıdır'}), 400
    
    user_group.is_admin = False
    
    try:
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/group/<int:group_id>/member/<int:user_id>/remove', methods=['POST'])
@login_required
def remove_group_member(group_id, user_id):
    group = Group.query.get_or_404(group_id)
    
    # Specific check for SKYNEX group: only NEXUS can manage members
    if group.name == 'SKYNEX':
        if not is_nexus(current_user):
            return jsonify({'success': False, 'error': 'Bu grubun üyelerini yönetme yetkiniz yok'}), 403
    else:
        # For other groups, check if current user is admin
        is_admin = UserGroups.query.filter_by(
            user_id=current_user.id,
            group_id=group_id,
            is_admin=True
        ).first()
        if not is_admin:
            return jsonify({'success': False, 'error': 'Bu grubun üyelerini yönetme yetkiniz yok'}), 403
    
    # Prevent removing NEXUS from SKYNEX or the last admin
    if group.name == 'SKYNEX' and user_id == User.query.filter_by(username='NEXUS').first().id:
        return jsonify({'success': False, 'error': 'NEXUS kullanıcısı SKYNEX grubundan çıkarılamaz'}), 400
    
    user_group = UserGroups.query.filter_by(
        user_id=user_id,
        group_id=group_id
    ).first()
    
    if not user_group:
        return jsonify({'success': False, 'error': 'Kullanıcı bu grubun üyesi değil'}), 400
    
    # Don't allow removing the last admin if the user to be removed is an admin
    if user_group.is_admin:
        admin_count = UserGroups.query.filter_by(group_id=group_id, is_admin=True).count()
        if admin_count <= 1:
            return jsonify({'success': False, 'error': 'Grupta en az bir admin olmalıdır'}), 400
    
    db.session.delete(user_group)
    
    try:
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/group/<int:group_id>/settings', methods=['POST'])
@login_required
def update_group_settings(group_id):
    group = Group.query.get_or_404(group_id)
    
    # Specific check for SKYNEX group: only NEXUS can change settings
    if group.name == 'SKYNEX':
        if not is_nexus(current_user):
            return jsonify({'success': False, 'error': 'Bu grubun ayarlarını değiştirme yetkiniz yok'}), 403
    else:
        # For other groups, check if current user is admin
        is_admin = UserGroups.query.filter_by(
            user_id=current_user.id,
            group_id=group_id,
            is_admin=True
        ).first()
        if not is_admin:
            return jsonify({'success': False, 'error': 'Bu grubun ayarlarını değiştirme yetkiniz yok'}), 403
    
    data = request.get_json()
    description = data.get('description')
    is_private = data.get('is_private')
    
    if description is not None:
        group.description = description
    
    if is_private is not None:
        group.is_private = is_private
    
    try:
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

# SKYNEX grubunu oluştur
def create_skynex_group():
    with app.app_context():
        skynex_group = Group.query.filter_by(name='SKYNEX').first()
        if not skynex_group:
            skynex_group = Group(
                name='SKYNEX',
                description='SKYNEX özel grubu',
                created_by=1,  # Admin user ID
                is_special=True
            )
            db.session.add(skynex_group)
            db.session.commit()
            print("SKYNEX grubu oluşturuldu!")

@app.route('/toggle_theme', methods=['POST'])
@login_required
def toggle_theme():
    if current_user.theme == 'light':
        current_user.theme = 'dark'
    else:
        current_user.theme = 'light'
    db.session.commit()
    return jsonify({'success': True})

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        # Tema ayarı
        theme = request.form.get('theme')
        if theme in ['light', 'dark']:
            current_user.theme = theme
            db.session.commit()
            flash('Tema ayarı güncellendi.', 'success')
        
        # Bildirim ayarları
        email_notifications = request.form.get('email_notifications') == 'on'
        message_notifications = request.form.get('message_notifications') == 'on'
        
        current_user.email_notifications = email_notifications
        current_user.message_notifications = message_notifications
        db.session.commit()
        flash('Bildirim ayarları güncellendi.', 'success')
        
        return redirect(url_for('settings'))
    
    return render_template('settings.html', user=current_user)  # current_user'ı template'e gönder

@app.route('/groups')
@login_required
def groups():
    # SKYNEX grubunu hariç tut
    available_groups = Group.query.filter(Group.name != 'SKYNEX').all()
    user_groups = current_user.groups
    print('Kullanıcının grupları:', [g.name for g in user_groups])  # DEBUG
    return render_template('groups.html', available_groups=available_groups, user_groups=user_groups)

@app.route('/group/<int:group_id>/join', methods=['POST'])
@login_required
def join_group(group_id):
    group = Group.query.get_or_404(group_id)
    
    if group.is_private:
        return jsonify({'success': False, 'error': 'Bu grup özeldir. Katılım için istek göndermelisiniz.'})
    
    if UserGroups.query.filter_by(user_id=current_user.id, group_id=group_id).first():
        return jsonify({'success': False, 'error': 'Zaten bu grubun üyesisiniz'})
    
    user_group = UserGroups(user_id=current_user.id, group_id=group_id)
    db.session.add(user_group)
    
    try:
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/group/<int:group_id>/request_join', methods=['POST'])
@login_required
def request_join_group(group_id):
    group = Group.query.get_or_404(group_id)
    
    if not group.is_private:
        return jsonify({'success': False, 'error': 'Bu grup özel değil, direkt katılabilirsiniz'})
    
    if UserGroups.query.filter_by(user_id=current_user.id, group_id=group_id).first():
        return jsonify({'success': False, 'error': 'Zaten bu grubun üyesisiniz'})
    
    existing_request = GroupJoinRequest.query.filter_by(
        user_id=current_user.id,
        group_id=group_id,
        status='pending'
    ).first()
    
    if existing_request:
        return jsonify({'success': False, 'error': 'Zaten bekleyen bir katılım isteğiniz var'})
    
    join_request = GroupJoinRequest(
        user_id=current_user.id,
        group_id=group_id,
        status='pending'
    )
    db.session.add(join_request)
    
    try:
        db.session.commit()
        
        # Notify group admins
        admins = UserGroups.query.filter_by(group_id=group_id, is_admin=True).all()
        for admin in admins:
            notification = Notification(
                user_id=admin.user_id,
                type='group_join_request',
                content=f'{current_user.username} grubunuza katılmak istiyor',
                related_id=join_request.id
            )
            db.session.add(notification)
            socketio.emit('notification', {
                'user_id': admin.user_id,
                'type': 'group_join_request',
                'content': f'{current_user.username} grubunuza katılmak istiyor',
                'group_id': group_id
            }, room=f'user_{admin.user_id}')
        
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/group/join_requests')
@login_required
def get_join_requests():
    # Get all groups where user is admin
    admin_groups = UserGroups.query.filter_by(user_id=current_user.id, is_admin=True).all()
    group_ids = [ug.group_id for ug in admin_groups]
    
    # Get pending join requests for these groups
    requests = GroupJoinRequest.query.filter(
        GroupJoinRequest.group_id.in_(group_ids),
        GroupJoinRequest.status == 'pending'
    ).join(User).join(Group).all()
    
    requests_data = [{
        'id': req.id,
        'username': req.user.username,
        'group_name': req.group.name,
        'created_at': req.created_at.strftime('%d.%m.%Y %H:%M')
    } for req in requests]
    
    return jsonify({
        'success': True,
        'requests': requests_data
    })

@app.route('/group/join_request/<int:request_id>/<action>', methods=['POST'])
@login_required
def handle_join_request(request_id, action):
    if action not in ['accept', 'reject']:
        return jsonify({'success': False, 'error': 'Geçersiz işlem'})
    
    join_request = GroupJoinRequest.query.get_or_404(request_id)
    
    # Check if user is admin of the group
    is_admin = UserGroups.query.filter_by(
        user_id=current_user.id,
        group_id=join_request.group_id,
        is_admin=True
    ).first()
    
    if not is_admin:
        return jsonify({'success': False, 'error': 'Bu işlem için yetkiniz yok'})
    
    if join_request.status != 'pending':
        return jsonify({'success': False, 'error': 'Bu istek zaten işlenmiş'})
    
    if action == 'accept':
        # Add user to group
        user_group = UserGroups(user_id=join_request.user_id, group_id=join_request.group_id)
        db.session.add(user_group)
        
        # Create notification for the user
        notification = Notification(
            user_id=join_request.user_id,
            type='group_join_accepted',
            content=f'{join_request.group.name} grubuna katılım isteğiniz kabul edildi',
            related_id=join_request.group_id
        )
        db.session.add(notification)
        
        # Send socket notification
        socketio.emit('notification', {
            'user_id': join_request.user_id,
            'type': 'group_join_accepted',
            'content': f'{join_request.group.name} grubuna katılım isteğiniz kabul edildi',
            'group_id': join_request.group_id
        }, room=f'user_{join_request.user_id}')
    
    join_request.status = 'accepted' if action == 'accept' else 'rejected'
    join_request.processed_at = datetime.utcnow()
    join_request.processed_by = current_user.id
    
    try:
        db.session.commit()
        return jsonify({
            'success': True,
            'user_id': join_request.user_id,
            'group_name': join_request.group.name,
            'group_id': join_request.group_id
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/group/<int:group_id>/management')
@login_required
def group_management(group_id):
    group = Group.query.get_or_404(group_id)
    
    # Specific check for SKYNEX group: only NEXUS can manage
    if group.name == 'SKYNEX':
        if not is_nexus(current_user):
            return jsonify({'success': False, 'error': 'Bu grubu yönetme yetkiniz yok'}), 403
    else:
        # For other groups, check if user is admin of this group or a super admin
        is_group_admin = UserGroups.query.filter_by(
            user_id=current_user.id,
            group_id=group_id,
            is_admin=True
        ).first()
        if not is_group_admin and not is_super_admin(current_user):
            return jsonify({'success': False, 'error': 'Bu grubu yönetme yetkiniz yok'}), 403
    
    # Get group members
    members = UserGroups.query.filter_by(group_id=group_id).join(User).all()
    
    html = render_template('group_management.html',
        group=group,
        members=members
    )
    
    return jsonify({
        'success': True,
        'html': html
    })

@app.route('/create_group', methods=['POST'])
@login_required
def create_group():
    if not current_user.has_permission('create_group'):
        return jsonify({'success': False, 'error': 'Bu işlem için yetkiniz yok'})
    
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    is_private = data.get('is_private', False)
    
    if not name:
        return jsonify({'success': False, 'error': 'Grup adı gerekli'})
    
    group = Group(name=name, description=description, is_private=is_private, creator_id=current_user.id)
    db.session.add(group)
    
    # Add creator as admin
    user_group = UserGroups(user_id=current_user.id, group_id=group.id, is_admin=True)
    db.session.add(user_group)
    
    try:
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

PASSWORD_FILE = 'site_password.txt'

# Giriş şifresi kontrol decorator'u
def require_site_password(view_func):
    def wrapper(*args, **kwargs):
        allowed_routes = ['gate', 'static']
        if 'site_password_ok' not in session and request.endpoint not in allowed_routes:
            return redirect(url_for('gate'))
        return view_func(*args, **kwargs)
    wrapper.__name__ = view_func.__name__
    return wrapper

@app.route('/gate', methods=['GET', 'POST'])
def gate():
    error = None
    if request.method == 'POST':
        with open(PASSWORD_FILE, 'r') as f:
            real_password = f.read().strip()
        password = request.form.get('password', '')
        if password == real_password:
            session['site_password_ok'] = True
            # Redirect to the login page after successful gate entry
            return redirect(url_for('login'))
        else:
            error = 'Hatalı şifre!'
    return render_template('gate.html', error=error)

# Tüm önemli route'lara şifre kontrolü ekle
for rule in app.url_map.iter_rules():
    if rule.endpoint not in ['static', 'gate']:
        view_func = app.view_functions[rule.endpoint]
        app.view_functions[rule.endpoint] = require_site_password(view_func)

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    try:
        content = request.form.get('content', '').strip()
        room = request.form.get('room')
        
        if not content:
            return jsonify({'success': False, 'error': 'Mesaj içeriği boş olamaz'})
            
        if not room:
            return jsonify({'success': False, 'error': 'Oda bilgisi gerekli'})
            
        # Kullanıcının yasaklı olup olmadığını kontrol et
        if current_user.is_banned:
            if current_user.banned_until and current_user.banned_until > datetime.utcnow():
                return jsonify({'success': False, 'error': f'Hesabınız {current_user.banned_until.strftime("%d.%m.%Y %H:%M")} tarihine kadar yasaklanmıştır'})
            else:
                current_user.is_banned = False
                current_user.banned_until = None
                db.session.commit()
        
        # Kullanıcının susturulmuş olup olmadığını kontrol et
        if current_user.is_muted:
            if current_user.muted_until and current_user.muted_until > datetime.utcnow():
                return jsonify({'success': False, 'error': f'Hesabınız {current_user.muted_until.strftime("%d.%m.%Y %H:%M")} tarihine kadar susturulmuştur'})
            else:
                current_user.is_muted = False
                current_user.muted_until = None
                db.session.commit()
        
        print(f"Mesaj gönderme denemesi - Kullanıcı: {current_user.username}")
        print(f"Mesaj içeriği: {content}")
        print(f"Hedef oda: {room}")
        
        # Mesaj gönderme işlemleri
        if room == 'anonymous':
            message = Message(
                content=content,
                user_id=current_user.id,
                room=room,
                timestamp=datetime.now(ZoneInfo('Europe/Istanbul'))
            )
            db.session.add(message)
            db.session.commit()
            
            profile_map = {
                'standart': 'standart.png',
                'giyuu': 'giyuu.png',
                'standartkiz': 'standartkiz.png',
            }
            profile_file = profile_map.get(current_user.anonymous_profile, 'standart.png')
            
            message_data = {
                'id': message.id,
                'content': content,
                'timestamp': message.timestamp.astimezone(ZoneInfo('Europe/Istanbul')).strftime('%d.%m.%Y %H:%M'),
                'room': room,
                'user_id': current_user.id,
                'username': 'Anonim',
                'profile_image_url': url_for('static', filename=f'images/{profile_file}'),
                'is_anonymous': True
            }
            socketio.emit('new_message', message_data, room=room)
            print(f"Anonim mesaj başarıyla gönderildi: {current_user.username} -> {content}")
            
        elif room == 'global':
            message = Message(
                content=content,
                user_id=current_user.id,
                room=room,
                timestamp=datetime.now(ZoneInfo('Europe/Istanbul'))
            )
            db.session.add(message)
            db.session.commit()
            
            message_data = {
                'id': message.id,
                'content': content,
                'timestamp': message.timestamp.astimezone(ZoneInfo('Europe/Istanbul')).strftime('%d.%m.%Y %H:%M'),
                'room': room,
                'user_id': current_user.id,
                'username': current_user.username,
                'profile_image_url': current_user.profile_image_url or url_for('static', filename='images/default.png'),
                'is_anonymous': False,
                'role': current_user.role
            }
            socketio.emit('new_message', message_data, room=room)
            print(f"Global mesaj başarıyla gönderildi: {current_user.username} -> {content}")
            
        elif room.startswith('group_'):
            group_id = int(room.split('_')[1])
            group = Group.query.get(group_id)
            if not group:
                return jsonify({'success': False, 'error': 'Grup bulunamadı'})
            if group not in current_user.groups:
                return jsonify({'success': False, 'error': 'Bu grupta mesaj gönderme yetkiniz yok'})
            
            message = Message(
                content=content,
                user_id=current_user.id,
                room=room,
                timestamp=datetime.now(ZoneInfo('Europe/Istanbul'))
            )
            db.session.add(message)
            db.session.commit()
            
            message_data = {
                'id': message.id,
                'content': content,
                'timestamp': message.timestamp.astimezone(ZoneInfo('Europe/Istanbul')).strftime('%d.%m.%Y %H:%M'),
                'room': room,
                'user_id': current_user.id,
                'username': current_user.username,
                'profile_image_url': current_user.profile_image_url or url_for('static', filename='images/default.png'),
                'is_anonymous': False,
                'role': current_user.role
            }
            socketio.emit('new_message', message_data, room=room)
            print(f"Grup mesajı başarıyla gönderildi: {current_user.username} -> {group.name} -> {content}")
        
        return jsonify({'success': True, 'message': 'Mesaj başarıyla gönderildi'})
            
    except Exception as e:
        db.session.rollback()
        print(f"Mesaj gönderme hatası: {str(e)}")
        print(f"Hata detayı: {type(e).__name__}")
        return jsonify({'success': False, 'error': 'Mesaj gönderilirken bir hata oluştu'})

@app.route('/search_users')
@login_required
def search_users():
    if not is_super_admin(current_user):
        return jsonify({'error': 'Yetkisiz erişim'}), 403
        
    query = request.args.get('query', '').strip()
    if not query:
        return jsonify({'users': []})
        
    try:
        # Kullanıcı adına göre arama yap
        users = User.query.filter(User.username.ilike(f'%{query}%')).limit(10).all()
        
        # Sonuçları JSON formatına dönüştür
        users_data = [{
            'id': user.id,
            'username': user.username,
            'role': user.role
        } for user in users]
        
        return jsonify({'users': users_data})
    except Exception as e:
        print(f"Kullanıcı arama hatası: {str(e)}")
        return jsonify({'error': 'Kullanıcı arama sırasında bir hata oluştu'}), 500

@app.route('/banned')
def banned():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    if not current_user.is_banned:
        return redirect(url_for('chat'))
    
    return render_template('banned.html', ban_until=current_user.banned_until)

# DM (Direct Message) Route'ları
@app.route('/messages')
@login_required
def messages():
    # Tüm kullanıcıları getir (kendisi hariç)
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('messages.html', users=users)

@app.route('/api/messages/<int:user_id>')
@login_required
def get_messages(user_id):
    # İki kullanıcı arasındaki mesajları getir
    messages = DirectMessage.query.filter(
        ((DirectMessage.sender_id == current_user.id) & (DirectMessage.receiver_id == user_id)) |
        ((DirectMessage.sender_id == user_id) & (DirectMessage.receiver_id == current_user.id))
    ).order_by(DirectMessage.timestamp).all()
    
    # Mesajları okundu olarak işaretle
    for message in messages:
        if message.receiver_id == current_user.id and not message.is_read:
            message.is_read = True
    db.session.commit()
    
    messages_data = []
    for message in messages:
        messages_data.append({
            'id': message.id,
            'content': message.content,
            'timestamp': message.timestamp.astimezone(ZoneInfo('Europe/Istanbul')).strftime('%d.%m.%Y %H:%M'),
            'sender_id': message.sender_id,
            'receiver_id': message.receiver_id,
            'is_read': message.is_read,
            'is_own': message.sender_id == current_user.id
        })
    
    return jsonify({'messages': messages_data})

@app.route('/api/send_dm', methods=['POST'])
@login_required
def send_dm():
    data = request.get_json()
    receiver_id = data.get('receiver_id')
    content = data.get('content', '').strip()
    
    if not content:
        return jsonify({'success': False, 'error': 'Mesaj boş olamaz'})
    
    if not receiver_id:
        return jsonify({'success': False, 'error': 'Alıcı belirtilmedi'})
    
    receiver = User.query.get(receiver_id)
    if not receiver:
        return jsonify({'success': False, 'error': 'Alıcı bulunamadı'})
    
    # Mesajı veritabanına kaydet
    message = DirectMessage(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        content=content
    )
    db.session.add(message)
    db.session.commit()
    
    # Socket.io ile gerçek zamanlı gönder
    message_data = {
        'id': message.id,
        'content': content,
        'timestamp': message.timestamp.astimezone(ZoneInfo('Europe/Istanbul')).strftime('%d.%m.%Y %H:%M'),
        'sender_id': current_user.id,
        'receiver_id': receiver_id,
        'is_read': False,
        'sender_username': current_user.username,
        'sender_profile': current_user.profile_image_url or url_for('static', filename='images/default.png')
    }
    
    # Hem gönderen hem alıcıya mesajı gönder
    socketio.emit('new_dm', message_data, room=f'user_{current_user.id}')
    socketio.emit('new_dm', message_data, room=f'user_{receiver_id}')
    
    return jsonify({'success': True, 'message': message_data})

@app.route('/api/users')
@login_required
def get_users():
    # Tüm kullanıcıları getir (kendisi hariç)
    users = User.query.filter(User.id != current_user.id).all()
    users_data = []
    
    for user in users:
        # Son mesajı al
        last_message = DirectMessage.query.filter(
            ((DirectMessage.sender_id == current_user.id) & (DirectMessage.receiver_id == user.id)) |
            ((DirectMessage.sender_id == user.id) & (DirectMessage.receiver_id == current_user.id))
        ).order_by(DirectMessage.timestamp.desc()).first()
        
        # Okunmamış mesaj sayısını al
        unread_count = DirectMessage.query.filter(
            DirectMessage.sender_id == user.id,
            DirectMessage.receiver_id == current_user.id,
            DirectMessage.is_read == False
        ).count()
        
        users_data.append({
            'id': user.id,
            'username': user.username,
            'role': user.role,
            'profile_image': user.profile_image_url or url_for('static', filename='images/default.png'),
            'last_message': last_message.content if last_message else None,
            'last_message_time': last_message.timestamp.astimezone(ZoneInfo('Europe/Istanbul')).strftime('%d.%m.%Y %H:%M') if last_message else None,
            'unread_count': unread_count
        })
    
    return jsonify({'users': users_data})

@app.route('/api/current_user')
@login_required
def get_current_user():
    return jsonify({
        'id': current_user.id,
        'username': current_user.username
    })

# Socket.io DM event'leri
@socketio.on('join_dm')
def handle_join_dm(data):
    if current_user.is_authenticated:
        user_id = current_user.id
        room = f'user_{user_id}'
        join_room(room)
        print(f"Kullanıcı {current_user.username} DM odasına katıldı: {room}")

@socketio.on('disconnect')
def handle_disconnect():
    global system_messages
    if current_user.is_authenticated:
        print(f"Kullanıcı {current_user.username} bağlantısı kesildi")
        user_left_msg = {
            'id': None,
            'content': f'"{current_user.username}" kullanıcısının bağlantısı kesildi',
            'timestamp': datetime.now(ZoneInfo('Europe/Istanbul')).strftime('%d.%m.%Y %H:%M'),
            'room': 'global',
            'user_id': None,
            'username': 'SYSTEM',
            'profile_image_url': '/static/images/default.png',
            'is_anonymous': False,
            'role': 'SYSTEM',
            'is_system': True,
            'system_type': 'disconnect',
            'system_username': current_user.username
        }
        system_messages.append(user_left_msg)
        if len(system_messages) > 100:
            system_messages.pop(0)
        # Tüm kullanıcılara disconnect mesajını gönder (broadcast=True)
        emit('new_message', user_left_msg, room='global', broadcast=True)

@app.route('/polls', methods=['GET', 'POST'])
@login_required
def polls():
    # Kullanıcı günde 1 defa anket oluşturabilir
    can_create = True
    today = datetime.utcnow().date()
    last_poll = Poll.query.filter_by(created_by=current_user.id).order_by(Poll.created_at.desc()).first()
    if last_poll and last_poll.created_at.date() == today:
        can_create = False

    if request.method == 'POST' and can_create:
        question = request.form.get('question', '').strip()
        options = [opt.strip() for opt in request.form.getlist('options') if opt.strip()]
        options = list(dict.fromkeys(options))  # Tekrarlı seçenekleri kaldır
        if not question or len(options) < 2:
            flash('Anket sorusu ve en az 2 seçenek gerekli.', 'danger')
        else:
            poll = Poll(question=question, created_by=current_user.id)
            db.session.add(poll)
            db.session.flush()  # poll.id almak için
            for opt in options:
                db.session.add(PollOption(poll_id=poll.id, text=opt))
            db.session.commit()
            flash('Anket başarıyla oluşturuldu!', 'success')
            return redirect(url_for('polls'))

    # Tüm anketleri ve seçenekleri, oylarla birlikte getir
    polls = Poll.query.order_by(Poll.created_at.desc()).all()
    poll_data = []
    for poll in polls:
        options = PollOption.query.filter_by(poll_id=poll.id).all()
        votes = PollVote.query.filter_by(poll_id=poll.id).all()
        option_votes = {opt.id: [] for opt in options}
        for vote in votes:
            option_votes[vote.option_id].append(vote.voter)
        user_voted = any(v.user_id == current_user.id for v in votes)
        poll_data.append({
            'poll': poll,
            'options': options,
            'option_votes': option_votes,
            'user_voted': user_voted
        })
    return render_template('polls.html', poll_data=poll_data, can_create=can_create)

@app.route('/polls/vote', methods=['POST'])
@login_required
def vote_poll():
    poll_id = request.form.get('poll_id', type=int)
    option_id = request.form.get('option_id', type=int)
    poll = Poll.query.get_or_404(poll_id)
    # Kullanıcı daha önce bu ankete oy verdi mi?
    existing_vote = PollVote.query.filter_by(poll_id=poll_id, user_id=current_user.id).first()
    if existing_vote:
        flash('Bu ankete zaten oy verdiniz.', 'warning')
    else:
        vote = PollVote(poll_id=poll_id, option_id=option_id, user_id=current_user.id)
        db.session.add(vote)
        db.session.commit()
        flash('Oyunuz kaydedildi!', 'success')
    return redirect(url_for('polls'))

@app.route('/confession', methods=['GET', 'POST'])
@login_required
def confession():
    from datetime import date
    today = date.today()
    # Kullanıcı bugün itiraf etmiş mi?
    existing = Confession.query.filter(
        Confession.user_id == current_user.id,
        db.func.date(Confession.created_at) == today
    ).first()
    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        if not content:
            flash('İtiraf metni boş olamaz.', 'danger')
        elif existing:
            flash('Bugün zaten bir itiraf gönderdiniz.', 'warning')
        else:
            confession = Confession(user_id=current_user.id, content=content)
            db.session.add(confession)
            db.session.commit()
            flash('İtirafınız başarıyla gönderildi!', 'success')
            return redirect(url_for('confession'))
    # Son 20 itirafı çek
    confessions = Confession.query.order_by(Confession.created_at.desc()).limit(20).all()
    return render_template('confession.html', confessions=confessions, existing=existing)

@app.route('/anonchat')
@login_required
def anon_chat():
    return render_template('anon_chat.html')

@app.route('/messages/anonymous')
@login_required
def get_anon_messages():
    messages = Message.query.filter_by(room='anonymous').order_by(Message.timestamp.desc()).limit(100).all()
    result = []
    for msg in messages:
        item = {
            'id': msg.id,
            'content': msg.content,
            'timestamp': msg.timestamp.strftime('%d.%m.%Y %H:%M'),
            'nickname': msg.anon_nickname,
            'profile': msg.anon_profile
        }
        if current_user.username == 'NEXUS':
            user = User.query.get(msg.user_id)
            item['real_username'] = user.username if user else None
        result.append(item)
    return jsonify(result)

@socketio.on('send_anon_message')
def handle_send_anon_message(data):
    content = data.get('content', '').strip()
    nickname = data.get('nickname', 'Anonim')
    profile = data.get('profile', 'profile.png')
    if not content or not current_user.is_authenticated:
        return
    message = Message(
        content=content,
        user_id=current_user.id,
        room='anonymous',
        timestamp=datetime.now(ZoneInfo('Europe/Istanbul')),
        anon_nickname=nickname,
        anon_profile=profile
    )
    db.session.add(message)
    db.session.commit()
    message_data = {
        'id': message.id,
        'content': content,
        'timestamp': message.timestamp.astimezone(ZoneInfo('Europe/Istanbul')).strftime('%d.%m.%Y %H:%M'),
        'nickname': nickname,
        'profile': profile
    }
    emit('new_anon_message', message_data, broadcast=True)

active_anon_profiles = {}

@socketio.on('get_active_profiles')
def get_active_profiles():
    emit('active_profiles', list(active_anon_profiles.values()))

@socketio.on('select_profile')
def select_profile(data, *args):
    print('select_profile event received:', data)
    callback = args[0] if args else None
    if not current_user.is_authenticated:
        if callback: callback(False)
        return
    profile = data.get('profile')
    # profile13.png sadece NEXUS'a izin ver
    if profile == 'profile13.png' and current_user.username != 'NEXUS':
        if callback: callback(False)
        return
    # Başka biri kullanıyorsa izin verme
    if profile in active_anon_profiles.values() and active_anon_profiles.get(request.sid) != profile:
        if callback: callback(False)
        return
    active_anon_profiles[request.sid] = profile
    emit('active_profiles', list(active_anon_profiles.values()), broadcast=True)
    if callback: callback(True)

@socketio.on('disconnect')
def on_disconnect():
    if request.sid in active_anon_profiles:
        del active_anon_profiles[request.sid]
        emit('active_profiles', list(active_anon_profiles.values()), broadcast=True)

# Anonim mesajları her 5 dakikada bir silen görev
from models import Message

def delete_anon_messages():
    with app.app_context():
        deleted = Message.query.filter_by(room='anonymous').delete()
        db.session.commit()

def delete_chats():
    with app.app_context():
        deleted_anon = Message.query.filter_by(room='anonymous').delete()
        db.session.commit()

def delete_main_messages():
    with app.app_context():
        deleted = Message.query.filter_by(room='global').delete()
        db.session.commit()

def delete_dm_messages():
    with app.app_context():
        from models import DirectMessage
        deleted = DirectMessage.query.delete()
        db.session.commit()

# --- GLOBAL SYSTEM MESSAGES ---
system_messages = []

ALLOWED_STICKER_EXTENSIONS = {'png', 'jpg', 'jpeg'}
MAX_STICKER_SIZE = 1 * 1024 * 1024  # 1MB
import os

def allowed_sticker_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_STICKER_EXTENSIONS

@app.route('/upload_sticker', methods=['POST'])
@login_required
def upload_sticker():
    if 'sticker' not in request.files:
        return jsonify({'success': False, 'error': 'Dosya bulunamadı'}), 400
    file = request.files['sticker']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'Dosya seçilmedi'}), 400
    if not allowed_sticker_file(file.filename):
        return jsonify({'success': False, 'error': 'Sadece PNG ve JPG/JPEG dosyalarına izin verilir'}), 400
    file.seek(0, os.SEEK_END)
    file_length = file.tell()
    file.seek(0)
    if file_length > MAX_STICKER_SIZE:
        return jsonify({'success': False, 'error': 'Dosya boyutu 1MB geçemez'}), 400
    # Kullanıcı limiti kontrolü (NEXUS hariç)
    if current_user.username != 'NEXUS':
        from models import UserSticker
        sticker_count = UserSticker.query.filter_by(user_id=current_user.id).count()
        if sticker_count >= 100:
            return jsonify({'success': False, 'error': 'En fazla 100 emoji/çıkartma ekleyebilirsiniz'}), 400
    # Dosyayı kaydet
    filename = secure_filename(file.filename)
    upload_folder = os.path.join('static', 'user_stickers', str(current_user.id))
    os.makedirs(upload_folder, exist_ok=True)
    save_path = os.path.join(upload_folder, filename)
    file.save(save_path)
    # Veritabanına kaydet
    from models import UserSticker
    sticker_type = request.form.get('type', 'emoji')
    sticker = UserSticker(user_id=current_user.id, type=sticker_type, file_url='/' + save_path.replace('\\', '/'))
    db.session.add(sticker)
    db.session.commit()
    return jsonify({'success': True, 'file_url': sticker.file_url})

@app.route('/my_stickers')
@login_required
def my_stickers():
    from models import UserSticker
    stickers = UserSticker.query.filter_by(user_id=current_user.id).all()
    return jsonify({'stickers': [
        {'id': s.id, 'type': s.type, 'file_url': s.file_url, 'created_at': s.created_at.isoformat()}
        for s in stickers
    ]})

@app.route('/delete_sticker/<int:sticker_id>', methods=['POST'])
@login_required
def delete_sticker(sticker_id):
    from models import UserSticker
    sticker = UserSticker.query.get(sticker_id)
    if not sticker or sticker.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Yetkisiz veya bulunamadı'}), 403
    # Dosyayı sil
    try:
        file_path = sticker.file_url.lstrip('/')
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        pass
    db.session.delete(sticker)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/edit_message', methods=['POST'])
@login_required
def edit_message():
    data = request.get_json()
    message_id = data.get('message_id')
    new_content = data.get('content', '').strip()
    if not message_id or not new_content:
        return jsonify({'success': False, 'error': 'Eksik veri'}), 400
    msg = Message.query.get(message_id)
    if not msg or msg.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 403
    if not msg.edit_count:
        msg.edit_count = 0
    if msg.edit_count >= 1:
        return jsonify({'success': False, 'error': 'Bu mesaj sadece 1 defa düzenlenebilir'}), 400
    msg.content = new_content
    msg.edited = True
    msg.edit_count = 1
    db.session.commit()
    return jsonify({'success': True, 'edited': True, 'content': new_content})

@app.route('/api/edit_dm', methods=['POST'])
@login_required
def edit_dm():
    data = request.get_json()
    message_id = data.get('message_id')
    new_content = data.get('content', '').strip()
    if not message_id or not new_content:
        return jsonify({'success': False, 'error': 'Eksik veri'}), 400
    msg = DirectMessage.query.get(message_id)
    if not msg or msg.sender_id != current_user.id:
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 403
    if not msg.edit_count:
        msg.edit_count = 0
    if msg.edit_count >= 1:
        return jsonify({'success': False, 'error': 'Bu mesaj sadece 1 defa düzenlenebilir'}), 400
    msg.content = new_content
    msg.edited = True
    msg.edit_count = 1
    db.session.commit()
    # Anlık güncelleme için socket event gönder
    from flask_socketio import SocketIO
    message_data = {
        'id': msg.id,
        'content': new_content,
        'timestamp': msg.timestamp.astimezone(ZoneInfo('Europe/Istanbul')).strftime('%d.%m.%Y %H:%M'),
        'sender_id': msg.sender_id,
        'receiver_id': msg.receiver_id,
        'is_read': msg.is_read,
        'sender_username': msg.sender.username if msg.sender else '',
        'sender_profile': msg.sender.profile_image_url if msg.sender else '',
        'edited': True,
        'edit_count': 1
    }
    socketio.emit('edit_dm', message_data, room=f'user_{msg.sender_id}')
    socketio.emit('edit_dm', message_data, room=f'user_{msg.receiver_id}')
    return jsonify({'success': True, 'edited': True, 'content': new_content})

# --- DEVICE TOKEN RESET FOR PREDEFINED USERS ---
@app.route('/admin/reset_device_token/<username>', methods=['POST'])
@login_required
def reset_device_token(username):
    if not is_nexus(current_user):
        return jsonify({'success': False, 'error': 'Sadece NEXUS kullanıcısı bu işlemi yapabilir.'}), 403
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'success': False, 'error': 'Kullanıcı bulunamadı'}), 404
    user.device_token = None
    db.session.commit()
    return jsonify({'success': True, 'message': f"{username} kullanıcısının cihaz kaydı sıfırlandı."})

# --- SETTINGS MANAGEMENT ---
SETTINGS_FILE = os.path.join('instance', 'settings.json')

def load_settings():
    try:
        with open(SETTINGS_FILE, 'r') as f:
            data = json.load(f)
            app.config['MAINTENANCE_MODE'] = data.get('MAINTENANCE_MODE', False)
            app.config['REGISTRATION_OPEN'] = data.get('REGISTRATION_OPEN', True)
    except Exception:
        app.config['MAINTENANCE_MODE'] = False
        app.config['REGISTRATION_OPEN'] = True

def save_settings():
    data = {
        'MAINTENANCE_MODE': app.config['MAINTENANCE_MODE'],
        'REGISTRATION_OPEN': app.config['REGISTRATION_OPEN']
    }
    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(data, f)

# --- NEXUS PANEL ---
from flask import render_template, request as flask_request
@app.route('/nexus_panel', methods=['GET', 'POST'])
@login_required
def nexus_panel():
    if not is_nexus(current_user):
        return abort(403)
    message = None
    if flask_request.method == 'POST':
        if 'maintenance_mode' in flask_request.form:
            app.config['MAINTENANCE_MODE'] = flask_request.form.get('maintenance_mode') == 'on'
        else:
            app.config['MAINTENANCE_MODE'] = False
        if 'registration_open' in flask_request.form:
            app.config['REGISTRATION_OPEN'] = flask_request.form.get('registration_open') == 'on'
        else:
            app.config['REGISTRATION_OPEN'] = False
        save_settings()
        if 'site_password' in flask_request.form:
            set_site_password(flask_request.form.get('site_password', ''))
            message = 'Ayarlar kaydedildi.'
        else:
            message = 'Ayarlar kaydedildi.'
        # Reload settings to reflect changes
        load_settings()
    return render_template('nexus_panel.html', user=current_user, 
        maintenance_mode=app.config.get('MAINTENANCE_MODE', False),
        registration_open=app.config.get('REGISTRATION_OPEN', True),
        site_password=get_site_password(),
        message=message)

# Site password fonksiyonları
SITE_PASSWORD_FILE = 'site_password.txt'
def get_site_password():
    try:
        with open(SITE_PASSWORD_FILE, 'r') as f:
            return f.read().strip()
    except Exception:
        return ''
        
def set_site_password(new_password):
    with open(SITE_PASSWORD_FILE, 'w') as f:
        f.write(new_password.strip())

# NEXUS Admin Panel - Gelişmiş Yönetim Fonksiyonları
@app.route('/admin/reset_device_token/<username>', methods=['POST'])
@login_required
def admin_reset_device_token(username):
    if not is_nexus(current_user):
        return jsonify({'success': False, 'error': 'Sadece NEXUS kullanıcısı bu işlemi yapabilir.'}), 403
    
    # Case-insensitive ve kısmi arama yap
    user = User.query.filter(User.username.ilike(f'%{username}%')).first()
    if not user:
        return jsonify({'success': False, 'error': 'Kullanıcı bulunamadı.'})
    
    # Cihaz token'ını sıfırla
    user.device_token = None
    
    # Aktif session'ları da sıfırla
    UserSession.query.filter_by(user_id=user.id).delete()
    
    db.session.commit()
    return jsonify({'success': True, 'message': f'{username} kullanıcısının cihaz kaydı ve oturumları sıfırlandı.'})

@app.route('/admin/get_user_info/<username>', methods=['GET'])
@login_required
def admin_get_user_info(username):
    if not is_nexus(current_user):
        return jsonify({'success': False, 'error': 'Sadece NEXUS kullanıcısı bu işlemi yapabilir.'}), 403
    
    # Case-insensitive ve kısmi arama yap
    user = User.query.filter(User.username.ilike(f'%{username}%')).first()
    if not user:
        return jsonify({'success': False, 'error': 'Kullanıcı bulunamadı.'})
    
    # Aktif session sayısını al
    active_sessions = UserSession.query.filter_by(user_id=user.id, is_active=True).count()
    
    user_info = {
        'id': user.id,
        'username': user.username,
        'role': user.role,
        'is_banned': user.is_banned,
        'is_muted': user.is_muted,
        'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else 'Hiç giriş yapmamış',
        'last_ip': user.last_ip or 'Bilinmiyor',
        'device_token': 'Var' if user.device_token else 'Yok',
        'active_sessions': active_sessions,
        'theme': user.theme,
        'profile_image': user.profile_image
    }
    
    return jsonify({'success': True, 'user': user_info})

@app.route('/admin/get_all_users', methods=['GET'])
@login_required
def admin_get_all_users():
    if not is_nexus(current_user):
        return jsonify({'success': False, 'error': 'Sadece NEXUS kullanıcısı bu işlemi yapabilir.'}), 403
    
    users = User.query.all()
    users_list = []
    
    for user in users:
        active_sessions = UserSession.query.filter_by(user_id=user.id, is_active=True).count()
        users_list.append({
            'id': user.id,
            'username': user.username,
            'role': user.role,
            'is_banned': user.is_banned,
            'is_muted': user.is_muted,
            'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else 'Hiç giriş yapmamış',
            'device_token': 'Var' if user.device_token else 'Yok',
            'active_sessions': active_sessions
        })
    
    return jsonify({'success': True, 'users': users_list})

@app.route('/admin/reset_all_device_tokens', methods=['POST'])
@login_required
def admin_reset_all_device_tokens():
    if not is_nexus(current_user):
        return jsonify({'success': False, 'error': 'Sadece NEXUS kullanıcısı bu işlemi yapabilir.'}), 403
    
    # Tüm kullanıcıların cihaz token'larını sıfırla
    users = User.query.all()
    reset_count = 0
    
    for user in users:
        if user.device_token:
            user.device_token = None
            reset_count += 1
    
    # Tüm aktif session'ları da sıfırla
    UserSession.query.delete()
    
    db.session.commit()
    return jsonify({'success': True, 'message': f'{reset_count} kullanıcının cihaz kaydı ve tüm oturumlar sıfırlandı.'})

@app.route('/admin/reset_nexus_ryder_device_tokens', methods=['POST'])
@login_required
def reset_nexus_ryder_device_tokens():
    if not is_nexus(current_user):
        return jsonify({'success': False, 'error': 'Sadece NEXUS kullanıcısı bu işlemi yapabilir.'}), 403
    usernames = ['NEXUS', 'RYDER']
    updated = []
    for uname in usernames:
        user = User.query.filter_by(username=uname).first()
        if user:
            user.device_token = None
            updated.append(uname)
    db.session.commit()
    return jsonify({'success': True, 'message': f"{', '.join(updated)} kullanıcılarının cihaz kaydı sıfırlandı."})

@app.route('/admin/reset_nexus_device_token', methods=['POST'])
@login_required
def reset_nexus_device_token():
    if not is_nexus(current_user):
        return jsonify({'success': False, 'error': 'Sadece NEXUS kullanıcısı bu işlemi yapabilir.'}), 403
    
    nexus_user = User.query.filter_by(username='NEXUS').first()
    if nexus_user:
        nexus_user.device_token = None
        db.session.commit()
        return jsonify({'success': True, 'message': 'NEXUS kullanıcısının cihaz kaydı sıfırlandı.'})
    else:
        return jsonify({'success': False, 'error': 'NEXUS kullanıcısı bulunamadı.'})

# Scheduler ayarları (main/anon 3 dakikada bir, DM günlük)
if __name__ == '__main__':
    import os
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        with app.app_context():
            scheduler.add_job(id='delete_anon_messages', func=delete_anon_messages, trigger='interval', minutes=3)
            scheduler.add_job(id='delete_main_messages', func=delete_main_messages, trigger='interval', minutes=3)
            scheduler.add_job(id='delete_dm_messages', func=delete_dm_messages, trigger='interval', days=1)
            if not scheduler.running:
                scheduler.start()
            create_predefined_users()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000) 

# --- REGISTRATION ROUTE ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if not app.config.get('REGISTRATION_OPEN', True):
        return render_template('register.html', form=None, registration_closed=True)
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Kayıt başarılı! Giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form, registration_closed=False)

# --- MAINTENANCE MODE ---
@app.before_request
def maintenance_check():
    if app.config.get('MAINTENANCE_MODE', False):
        # Bakım modunda tüm kullanıcılar için izin verilen route'lar
        allowed_endpoints = ['login', 'static', 'logout']
        
        # NEXUS kullanıcıları için ek izin verilen route'lar
        nexus_endpoints = ['nexus_panel', 'index', 'chat', 'forum', 'polls']
        
        # Eğer kullanıcı NEXUS ise, NEXUS route'larına da erişebilir
        if current_user.is_authenticated and is_nexus(current_user):
            allowed_endpoints.extend(nexus_endpoints)
        
        # İzin verilen endpoint'lerden biri değilse engelle
        if request.endpoint not in allowed_endpoints:
            return render_template('banned.html', error='Site bakım modunda. Lütfen daha sonra tekrar deneyin.'), 503

# Load settings at startup
load_settings()