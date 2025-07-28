# SKYNEX Chat Platform

SKYNEX, modern ve kullanıcı dostu bir sohbet platformudur. Kullanıcılar arasında gerçek zamanlı iletişim sağlar ve çeşitli özellikler sunar.

## Özellikler

- 🎨 Modern ve duyarlı tasarım
- 🌓 Açık/Koyu tema desteği
- 👥 Kullanıcı yönetimi ve arkadaş sistemi
- 💬 Gerçek zamanlı sohbet
- 🔒 Güvenli kimlik doğrulama
- 👮‍♂️ Admin ve yardımcı admin rolleri
- 🚫 Kullanıcı yasaklama ve susturma sistemi
- 📱 Mobil uyumlu arayüz
- 🔔 Bildirim sistemi
- 🎭 Anonim sohbet seçeneği
- 📝 Mesaj raporlama sistemi

## Teknolojiler

- Backend: Python (Flask)
- Frontend: HTML, CSS, JavaScript
- Veritabanı: SQLite
- Gerçek zamanlı iletişim: Socket.IO
- UI Framework: Bootstrap 5
- İkonlar: Font Awesome

## Kurulum

1. Python 3.8 veya daha yüksek bir sürümü yükleyin.

2. Projeyi klonlayın:
```bash
git clone https://github.com/yourusername/skynex.git
cd skynex
```

3. Sanal ortam oluşturun ve etkinleştirin:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

4. Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
```

5. Veritabanını oluşturun:
```bash
flask db init
flask db migrate
flask db upgrade
```

6. Uygulamayı çalıştırın:
```bash
python app.py
```

7. Tarayıcınızda `http://localhost:5000` adresine gidin.

## Ortam Değişkenleri

`.env` dosyası oluşturun ve aşağıdaki değişkenleri ayarlayın:

```
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-email-password
SECRET_KEY=your-secret-key
```

## Kullanım

1. Kayıt olun veya giriş yapın
2. Global sohbete katılın
3. Arkadaş ekleyin ve mesajlaşın
4. Anonim sohbet veya DM'ler için farklı odaları kullanın
5. Tema tercihinizi değiştirin
6. Bildirimleri yönetin

## Admin Özellikleri

- Kullanıcıları yasaklama/susturma
- Yardımcı admin atama
- Mesaj raporlarını yönetme
- Kullanıcı rolleri düzenleme

## Katkıda Bulunma

1. Bu depoyu fork edin
2. Yeni bir özellik dalı oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add some amazing feature'`)
4. Dalınıza push edin (`git push origin feature/amazing-feature`)
5. Bir Pull Request açın

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Daha fazla bilgi için `LICENSE` dosyasına bakın.

## İletişim

Proje Sahibi - [@yourusername](https://github.com/yourusername)

Proje Linki: [https://github.com/yourusername/skynex](https://github.com/yourusername/skynex) 