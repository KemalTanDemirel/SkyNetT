#!/usr/bin/env python3
"""
SKYNEX - Device Token Reset Script
Bu script NEXUS ve RYDER kullanıcılarının cihaz bilgilerini sıfırlar.
"""

import sys
import os
from flask import Flask
from models import db, User, UserSession

# Flask app'i başlat
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///skynex.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Database'i başlat
db.init_app(app)

def reset_nexus_ryder_device_tokens():
    """NEXUS ve RYDER kullanıcılarının cihaz token'larını sıfırlar"""
    with app.app_context():
        usernames = ['NEXUS', 'RYDER']
        updated = []
        
        print("Cihaz token'ları sıfırlanıyor...")
        
        for username in usernames:
            user = User.query.filter_by(username=username).first()
            if user:
                if user.device_token:
                    user.device_token = None
                    updated.append(username)
                    print(f"[OK] {username} kullanıcısının cihaz token'ı sıfırlandı")
                else:
                    print(f"[INFO] {username} kullanıcısının zaten cihaz token'ı yok")
            else:
                print(f"[ERROR] {username} kullanıcısı bulunamadı")
        
        # İlgili kullanıcıların aktif session'larını da sıfırla
        if updated:
            for username in updated:
                user = User.query.filter_by(username=username).first()
                if user:
                    UserSession.query.filter_by(user_id=user.id).delete()
                    print(f"[OK] {username} kullanıcısının aktif session'ları silindi")
        
        # Değişiklikleri kaydet
        db.session.commit()
        
        if updated:
            print(f"\n[SUCCESS] Başarılı! {', '.join(updated)} kullanıcılarının cihaz bilgileri sıfırlandı.")
            print("Bu kullanıcılar artık yeniden giriş yaparak yeni cihaz kaydı oluşturabilirler.")
        else:
            print("\n[WARNING] Hiçbir kullanıcının cihaz token'ı sıfırlanmadı.")

def main():
    """Ana fonksiyon"""
    print("=" * 50)
    print("SKYNEX - Cihaz Token Sıfırlama Aracı")
    print("=" * 50)
    print("Bu araç NEXUS ve RYDER kullanıcılarının cihaz bilgilerini sıfırlar.")
    print()
    
    try:
        reset_nexus_ryder_device_tokens()
    except Exception as e:
        print(f"\n[ERROR] Hata oluştu: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
