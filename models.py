from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(50), default='Kullanıcı') # Default role set to 'Kullanıcı'
    is_banned = db.Column(db.Boolean, default=False)
    banned_until = db.Column(db.DateTime, nullable=True)
    device_token = db.Column(db.String(36), nullable=True) # Keep for potential future use or compatibility
    last_global_message_time = db.Column(db.Float, default=0.0) # New field for global chat rate limit
    last_login = db.Column(db.DateTime, nullable=True)
    last_ip = db.Column(db.String(45), nullable=True)
    theme = db.Column(db.String(20), default='light')
    profile_image_url = db.Column(db.String(200), nullable=True)
    description = db.Column(db.Text, nullable=True)
    can_create_groups = db.Column(db.Boolean, default=False)
    groups = db.relationship('Group', secondary='user_groups', backref=db.backref('members', lazy='dynamic'))
    anonymous_profile = db.Column(db.String(20), default='default')
    # email_notifications = db.Column(db.Boolean, default=True) # E-posta bildirimleri kaldırıldı
    message_notifications = db.Column(db.Boolean, default=True)
    profile_image = db.Column(db.String(120), default='default.jpg')
    is_muted = db.Column(db.Boolean, default=False)
    muted_until = db.Column(db.DateTime, nullable=True)
    login_attempts = db.Column(db.Integer, default=0)  # Başarısız giriş denemeleri
    last_attempt = db.Column(db.DateTime, nullable=True)  # Son giriş denemesi zamanı
    sessions = db.relationship('UserSession', backref='user', lazy=True, cascade="all, delete-orphan")

    # İlişkiler
    owned_groups = db.relationship('Group', backref='owner', lazy=True, foreign_keys='Group.created_by', overlaps="created_groups,creator")
    
    def __repr__(self):
        return f'<User {self.username}>'
        
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def is_banned_check(self):
        if self.is_banned and self.banned_until:
            if datetime.utcnow() > self.banned_until:
                self.is_banned = False
                self.banned_until = None
                db.session.commit()
                return False
            return True
        return self.is_banned
        
    def is_muted_check(self):
        if self.is_muted and self.muted_until:
            if datetime.utcnow() > self.muted_until:
                self.is_muted = False
                self.muted_until = None
                db.session.commit()
                return False
            return True
        return self.is_muted

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_special = db.Column(db.Boolean, default=False)
    is_private = db.Column(db.Boolean, default=False)
    creator = db.relationship('User', backref='created_groups', foreign_keys=[created_by], overlaps="owned_groups,owner")

class UserGroups(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

class GroupJoinRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime, nullable=True)
    processed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    group = db.relationship('Group', backref='join_requests')
    user = db.relationship('User', backref='group_join_requests', foreign_keys=[user_id])
    processor = db.relationship('User', backref='processed_requests', foreign_keys=[processed_by])

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)
    related_id = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_token = db.Column(db.String(36), nullable=False)
    last_accessed = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True) # Aktif oturum mu?

    def __repr__(self):
        return f'<UserSession {self.session_token} for User {self.user_id}>'

# Forum Modelleri
class ForumThread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=True) # Forumun ilk gönderisi
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_locked = db.Column(db.Boolean, default=False)
    posts = db.relationship('ForumPost', backref='thread', lazy=True)

class ForumPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    thread_id = db.Column(db.Integer, db.ForeignKey('forum_thread.id'), nullable=False)
    # Forum gönderilerine fotoğraf ekleme düşünülürse buraya bir alan eklenebilir

# DM (Direct Message) Modeli
class DirectMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    edited = db.Column(db.Boolean, default=False)
    edit_count = db.Column(db.Integer, default=0)
    
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

# --- POLL SYSTEM MODELS ---
class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(255), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    options = db.relationship('PollOption', backref='poll', cascade='all, delete-orphan', lazy=True)
    votes = db.relationship('PollVote', backref='poll', cascade='all, delete-orphan', lazy=True)
    
    creator = db.relationship('User', backref='created_polls', foreign_keys=[created_by])

class PollOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    text = db.Column(db.String(120), nullable=False)
    votes = db.relationship('PollVote', backref='option', cascade='all, delete-orphan', lazy=True)

class PollVote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('poll_option.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    voted_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    voter = db.relationship('User', backref='poll_votes', foreign_keys=[user_id]) 

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room = db.Column(db.String(50), default='global')
    is_reported = db.Column(db.Boolean, default=False) 
    anon_nickname = db.Column(db.String(32), nullable=True)
    anon_profile = db.Column(db.String(120), nullable=True)
    edited = db.Column(db.Boolean, default=False)
    edit_count = db.Column(db.Integer, default=0)

class Confession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='confessions') 

class UserSticker(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(10), nullable=False)  # 'emoji' veya 'sticker'
    file_url = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='stickers') 