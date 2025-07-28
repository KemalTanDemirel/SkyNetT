// static/js/anon_chat.js

// Ses efektleri
const sounds = {
    connect: new Audio('/static/sounds/connect.mp3'),
    message: new Audio('/static/sounds/message.mp3'),
    disconnect: new Audio('/static/sounds/disconnect.mp3')
};

// Ses çalma fonksiyonu
function playSound(soundName) {
    try {
        if (sounds[soundName]) {
            sounds[soundName].currentTime = 0;
            sounds[soundName].play().catch(e => console.log('Ses çalınamadı:', e));
        }
    } catch (e) {
        console.log('Ses hatası:', e);
    }
}

document.addEventListener('DOMContentLoaded', function() {
    // Kullanıcı değiştiyse localStorage temizliği
    const lastAnonUser = localStorage.getItem('anon_user');
    if (window.CURRENT_USER && lastAnonUser && lastAnonUser !== window.CURRENT_USER) {
        localStorage.removeItem('anon_nickname');
        localStorage.removeItem('anon_profile');
    }
    if (window.CURRENT_USER) {
        localStorage.setItem('anon_user', window.CURRENT_USER);
    }
    // --- Anonim profil ve nickname seçimi ---
    const modal = document.getElementById('anon-profile-modal');
    const mainChat = document.getElementById('anon-chat-main');
    const nicknameInput = document.getElementById('anon-nickname-input');
    const profileList = document.getElementById('anon-profile-list');
    const continueBtn = document.getElementById('anon-profile-continue');
    let selectedProfile = null;
    let selectedNickname = null;

    // Yalnızca ilk yüklemede modal/chat açma işlemi
    (function() {
        const savedNick = localStorage.getItem('anon_nickname');
        const savedProfile = localStorage.getItem('anon_profile');
        if (savedNick && savedProfile) {
            selectedNickname = savedNick;
            selectedProfile = savedProfile;
            nicknameInput.value = savedNick;
            // Profil seçili olarak işaretlensin
            setTimeout(function() {
                document.querySelectorAll('.anon-profile-option').forEach(img => {
                    if (img.dataset.profile === savedProfile) {
                        img.classList.add('selected');
                    } else {
                        img.classList.remove('selected');
                    }
                });
            }, 100);
            modal.style.display = 'none';
            mainChat.style.display = '';
        } else {
            modal.style.display = '';
            mainChat.style.display = 'none';
        }
    })();

    // localStorage kontrolü kaldırıldı, her girişte modal açılır
    let activeProfiles = [];

    // Socket ile aktif profilleri al
    const socket = io();
    
    // Socket bağlantı olayları
    socket.on('connect', function() {
        console.log('Anonim chat bağlantısı kuruldu');
        playSound('connect');
    });
    
    socket.on('disconnect', function() {
        console.log('Anonim chat bağlantısı kesildi');
        playSound('disconnect');
    });
    
    socket.emit('get_active_profiles');
    socket.on('active_profiles', function(list) {
        activeProfiles = list;
        updateProfileAvailability();
    });
    // Profil seçimi değiştiğinde sunucuya bildir (callback'siz)
    function selectProfile(profile) {
        selectedProfile = profile;
        localStorage.setItem('anon_profile', profile);
    }

    // Profil resimlerini yükle
    profileList.innerHTML = '';
    ANON_PROFILES.forEach((filename, idx) => {
        // profile13.png sadece NEXUS'a açık
        if(filename === 'profile13.png' && window.CURRENT_USER !== 'NEXUS') return;
        const img = document.createElement('img');
        img.src = (typeof ANON_PROFILE_PATH !== 'undefined' ? ANON_PROFILE_PATH : '/static/images/profiles/') + filename;
        img.className = 'anon-profile-option';
        img.alt = `Profil${idx+1}`;
        img.dataset.profile = filename;
        img.addEventListener('click', function() {
            if(img.classList.contains('disabled')) return;
            document.querySelectorAll('.anon-profile-option').forEach(el => el.classList.remove('selected'));
            img.classList.add('selected');
            selectedProfile = filename;
            selectProfile(filename);
            checkContinue();
        });
        profileList.appendChild(img);
    });

    function updateProfileAvailability() {
        document.querySelectorAll('.anon-profile-option').forEach(img => {
            if(activeProfiles.includes(img.dataset.profile)) {
                img.classList.add('disabled');
                img.style.opacity = 0.4;
                img.title = 'Bu profil şu anda başka bir kullanıcı tarafından kullanılıyor';
            } else {
                img.classList.remove('disabled');
                img.style.opacity = 1;
                img.title = '';
            }
        });
    }

    // Nickname ve profil seçimi kontrolü
    nicknameInput.addEventListener('input', checkContinue);
    function checkContinue() {
        if (nicknameInput.value.trim().length > 0 && selectedProfile && !activeProfiles.includes(selectedProfile)) {
            continueBtn.disabled = false;
        } else {
            continueBtn.disabled = true;
        }
    }

    // Benzersiz nickname kontrolü için ekrandaki tüm nicknameleri topla (case-insensitive, tekrarları filtrele)
    function getAllNicknames() {
        const nicks = Array.from(document.querySelectorAll('.anon-message-header')).map(e => e.textContent.split(' ')[0].toLowerCase());
        // Tekrarları filtrele
        return Array.from(new Set(nicks));
    }

    // Devam Et butonu
    continueBtn.addEventListener('click', function() {
        const nickname = nicknameInput.value.trim();
        if (!nickname || !selectedProfile) return;
        // Sadece NEXUS kullanıcısı için yasaklı kelime kontrolü atlanır
        const isNexus = (window.CURRENT_USER && window.CURRENT_USER.toLowerCase() === 'nexus');
        if (!isNexus) {
            const forbidden = ['nexus', 'kemal'];
            const lowerNick = nickname.toLowerCase();
            let hasForbidden = forbidden.some(word => lowerNick.includes(word));
            if (hasForbidden) {
                alert('Bu kullanıcı adı yasaklı kelime içeriyor.');
                return;
            }
            // Ekrandaki tüm nicknameleri benzersiz olarak kontrol et
            const allNicks = getAllNicknames();
            if (allNicks.includes(lowerNick)) {
                alert('Bu kullanıcı adı zaten kullanılıyor. Lütfen başka bir isim seçin.');
                return;
            }
        }
        selectedNickname = nickname;
        localStorage.setItem('anon_nickname', nickname);
        localStorage.setItem('anon_profile', selectedProfile);
        modal.style.display = 'none';
        mainChat.style.display = '';
    });

    // --- Chat fonksiyonları ---
    const messagesContainer = document.getElementById('anon-chat-messages');
    const form = document.getElementById('anon-chat-form');
    const input = document.getElementById('anon-message-input');
    const timerDiv = document.getElementById('anon-timer');
    let lastAnonMessageTime = 0;
    let timerInterval = null;

    // Rate limit için son mesaj zamanı
    // Mesajları yükle
    fetch('/messages/anonymous')
        .then(res => res.json())
        .then(messages => {
            renderMessages(messages);
        });

    // Mesaj gönderme
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        const now = Date.now();
        const diff = now - lastAnonMessageTime;
        if (diff < 5000) {
            startTimer(5 - Math.floor(diff / 1000));
            return;
        }
        const content = input.value.trim();
        if (!content) return;
        const nickname = selectedNickname || 'Anonim';
        const profile = selectedProfile || 'profile1.png';
        socket.emit('send_anon_message', { content, nickname, profile });
        input.value = '';
        lastAnonMessageTime = now;
        startTimer(5);
    });

    function startTimer(seconds) {
        clearInterval(timerInterval);
        let remaining = seconds;
        timerDiv.style.display = 'block';
        timerDiv.textContent = `Yeni mesaj için ${remaining} saniye bekleyin...`;
        // input.disabled = true; // Artık input disable edilmeyecek
        form.querySelector('button[type="submit"]').disabled = true;
        timerInterval = setInterval(function() {
            remaining--;
            if (remaining > 0) {
                timerDiv.textContent = `Yeni mesaj için ${remaining} saniye bekleyin...`;
            } else {
                clearInterval(timerInterval);
                timerDiv.style.display = 'none';
                // input.disabled = false;
                form.querySelector('button[type="submit"]').disabled = false;
            }
        }, 1000);
    }

    // Enter ile mesaj gönderme
    input.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            form.dispatchEvent(new Event('submit', {cancelable: true, bubbles: true}));
        }
    });

    // Yeni mesaj geldiğinde
    socket.on('new_anon_message', function(message) {
        addMessage(message);
        
        // Mesaj sesi çal (kendi mesajı değilse)
        if (message.real_username !== window.CURRENT_USER) {
            playSound('message');
        }
    });

    function renderMessages(messages) {
        messagesContainer.innerHTML = '';
        messages.forEach(msg => addMessage(msg));
    }

    function addMessage(msg) {
        const div = document.createElement('div');
        div.className = 'anon-message';
        const profile = msg.profile || 'profile1.png';
        const nickname = msg.nickname || 'Anonim';
        // NEXUS ise gerçek kullanıcı adı için tıklanabilir yap
        let nicknameHtml = escapeHtml(nickname);
        if (window.CURRENT_USER && window.CURRENT_USER.toLowerCase() === 'nexus' && msg.real_username) {
            nicknameHtml = `<span class="real-username-nexus" style="cursor:pointer;color:#e74c3c;text-decoration:underline;" data-real="${msg.real_username}">${escapeHtml(nickname)}</span>`;
        }
        div.innerHTML = `
            <img src="${(typeof ANON_PROFILE_PATH !== 'undefined' ? ANON_PROFILE_PATH : '/static/images/profiles/')}${profile}" class="anon-profile-img" alt="Anonim">
            <div class="anon-message-content">
                <div class="anon-message-header">${nicknameHtml} <span class="anon-message-time">${msg.timestamp}</span></div>
                <div>${escapeHtml(msg.content)}</div>
            </div>
        `;
        messagesContainer.insertBefore(div, messagesContainer.firstChild);
        // NEXUS için modal açma
        if (window.CURRENT_USER && window.CURRENT_USER.toLowerCase() === 'nexus' && msg.real_username) {
            const el = div.querySelector('.real-username-nexus');
            if (el) {
                el.addEventListener('click', function(e) {
                    e.stopPropagation();
                    showRealUserModal(msg.real_username, nickname);
                });
            }
        }
    }

    function escapeHtml(text) {
        var map = {
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, function(m) { return map[m]; });
    }

    // Modal fonksiyonu ekle
    function showRealUserModal(realUsername, nickname) {
        let modal = document.getElementById('realUserModal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'realUserModal';
            modal.innerHTML = `
                <div style="position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.5);z-index:9999;display:flex;align-items:center;justify-content:center;">
                    <div style="background:#23272b;color:#fff;padding:32px 40px;border-radius:16px;min-width:320px;max-width:90vw;box-shadow:0 8px 32px #0008;position:relative;">
                        <button id="closeRealUserModal" style="position:absolute;top:12px;right:16px;background:none;border:none;color:#fff;font-size:1.5em;cursor:pointer;">&times;</button>
                        <h4 style="margin-bottom:18px;">Gerçek Kullanıcı</h4>
                        <div><b>Anonim Nick:</b> ${escapeHtml(nickname)}</div>
                        <div style="margin-top:10px;"><b>Gerçek Kullanıcı Adı:</b> <span style="color:#e74c3c;">${escapeHtml(realUsername)}</span></div>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
            document.getElementById('closeRealUserModal').onclick = function() {
                modal.remove();
            };
            // Modal dışına tıklayınca kapat
            modal.querySelector('div').onclick = function(e) { e.stopPropagation(); };
            modal.onclick = function() { modal.remove(); };
        }
    }

    // Sekme kapatınca veya logout olunca localStorage temizle
    // Logout linkine tıklanınca da temizle
    document.querySelectorAll('a[href$="logout"]').forEach(function(link) {
        link.addEventListener('click', function() {
            localStorage.removeItem('anon_nickname');
            localStorage.removeItem('anon_profile');
        });
    });

    // Çıkış butonu ile anonim chatten çıkış
    document.getElementById('anon-exit-btn').addEventListener('click', function() {
        localStorage.removeItem('anon_nickname');
        localStorage.removeItem('anon_profile');
        selectedNickname = null;
        selectedProfile = null;
        modal.style.display = '';
        mainChat.style.display = 'none';
    });
});