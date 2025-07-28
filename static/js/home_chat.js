let currentRoom = 'global'; // Sadece global chat olacağı için varsayılan oda global
let messageContainer = document.getElementById('global-messages'); // Global chat mesajları
let messageInput = document.querySelector('#global-form textarea'); // Global chat textarea
let messageForm = document.getElementById('global-form'); // Global chat form
let isConnected = false;

// Socket.IO bağlantısı
const socket = io({
    reconnection: true,
    reconnectionAttempts: 10,
    reconnectionDelay: 1000
});

// Bağlantı durumu yönetimi
socket.on('connect', function() {
    console.log('Socket.IO bağlantısı kuruldu');
    isConnected = true;
    // showStatus('Bağlantı kuruldu', 'success'); // Base template'te varsa gerek yok
    // Bağlantı kurulunca global odaya katıl
    socket.emit('join_room', { room: currentRoom });
});

socket.on('disconnect', function() {
    console.log('Socket.IO bağlantısı kesildi');
    isConnected = false;
    // showStatus('Bağlantı kesildi, yeniden bağlanılıyor...', 'warning'); // Base template'te varsa gerek yok
    
    // Bağlantı kesilme sesi çal
    tryPlaySound(disconnectSound);
});

socket.on('connect_error', function(error) {
    console.error('Bağlantı hatası:', error);
    // showError('Bağlantı hatası oluştu', 'danger'); // Base template'te varsa gerek yok
});

socket.on('connection_status', function(data) {
    console.log('Bağlantı durumu:', data);
    // if (data.status === 'connected') {
    //     showStatus(`${data.username} olarak bağlandınız`, 'success'); // Base template'te varsa gerek yok
    // }
});

// --- SES DOSYALARI ---
const connectSound = new Audio('/static/sounds/connect.mp3');
const disconnectSound = new Audio('/static/sounds/disconnect.mp3'); // Dosya adını küçük harfle düzeltiyorum
const messageSound = new Audio('/static/sounds/message.mp3');
let soundUnlock = false;

function tryPlaySound(audio) {
    if (soundUnlock) {
        audio.currentTime = 0;
        audio.play().catch(error => {
            console.error('Ses çalma hatası:', error);
        });
    } else {
        const unlock = () => {
            soundUnlock = true;
            audio.currentTime = 0;
            audio.play().catch(error => {
                console.error('Ses çalma hatası:', error);
            });
            window.removeEventListener('click', unlock);
        };
        window.addEventListener('click', unlock);
    }
}

// Timer fonksiyonu ekle
function startTimer(seconds) {
    clearInterval(rateLimitTimerInterval);
    let remaining = seconds;
    rateLimitTimerElement.style.visibility = 'visible';
    rateLimitTimerElement.textContent = `Yeni mesaj için ${remaining} saniye bekleyin...`;
    messageInput.disabled = true;
    messageForm.querySelector('button[type="submit"]').disabled = true;
    rateLimitTimerInterval = setInterval(function() {
        remaining--;
        if (remaining > 0) {
            rateLimitTimerElement.textContent = `Yeni mesaj için ${remaining} saniye bekleyin...`;
        } else {
            clearInterval(rateLimitTimerInterval);
            rateLimitTimerElement.style.visibility = 'hidden';
            messageInput.disabled = false;
            messageForm.querySelector('button[type="submit"]').disabled = false;
        }
    }, 1000);
}

// Sayfa yüklendiğinde
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM fully loaded - home.html');
    console.log('Sayfa yüklendi, oda:', currentRoom);
    
    // Debug: Elementleri kontrol et
    console.log('messageInput element:', messageInput);
    console.log('messageForm element:', messageForm);
    console.log('messageContainer element:', messageContainer); // Added this too

    // İlk yüklemede global mesajları yükle
    loadMessages(currentRoom);
    
    // Mesaj gönderme formunu dinle
    if (messageForm) { // Elementin varlığını kontrol et
        messageForm.addEventListener('submit', function(e) {
            console.log('Submit event listener added (home)');
            e.preventDefault();
            const content = messageInput.value.trim();
            console.log('Form submit edildi (home), mesaj:', content);
            console.log('Input value (home):', messageInput.value);
            console.log('Hedef oda (home):', currentRoom);
            
            if (!content) {
                console.log('Boş mesaj, gönderme iptal edildi (home)');
                return;
            }
            
            // Socket.IO ile mesaj gönder
            console.log('Socket.IO mesaj gönderiliyor (home):', { content, room: currentRoom });
            socket.emit('send_message', {
                content: content,
                room: currentRoom
            }, function(response) {
                console.log('Socket.IO yanıtı (home):', response);
                if (response && response.error) {
                    // showError(response.error); // Base template'te varsa gerek yok
                } else {
                    // Input'u temizle
                    messageInput.value = '';
                    messageInput.style.height = 'auto';
                    messageInput.focus();
                }
            });
        });
    } else {
        console.error('Message form element not found!'); // Error log if form is null
    }

    // Enter tuşu ile mesaj gönderme
    if (messageInput) { // Elementin varlığını kontrol et
        messageInput.addEventListener('keydown', function(e) {
            console.log('Keydown event listener added (home)');
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault(); // Enter tuşunun varsayılan davranışını engelle
                if (messageForm) { // Formun varlığını tekrar kontrol et
                    messageForm.dispatchEvent(new Event('submit')); // Form submit olayını tetikle
                } else {
                    console.error('Message form element not found during keydown!');
                }
            }
        });

        // Textarea otomatik yükseklik ayarı
        messageInput.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = (this.scrollHeight) + 'px';
        });
    } else {
        console.error('Message input element not found!'); // Error log if input is null
    }

    // --- MODERN EMOJI PICKER ---
    document.querySelectorAll('.emoji-panel').forEach(panel => panel.style.display = 'none'); // Tüm panelleri başta kapalı yap

    document.querySelectorAll('.emoji-btn').forEach(function(btn) {
        const inputGroup = btn.closest('.input-group');
        const panel = inputGroup.querySelector('.emoji-panel');
        const input = inputGroup.querySelector('textarea, input');
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            // Diğer açık panelleri kapat
            document.querySelectorAll('.emoji-panel').forEach(p => { if (p !== panel) p.style.display = 'none'; });
            panel.style.display = (panel.style.display === 'none' || !panel.style.display) ? 'grid' : 'none';
        });
        function handleEmojiSelect(e) {
            let emojiSpan = e.target;
            if (!emojiSpan.classList.contains('emoji')) {
                emojiSpan = emojiSpan.closest('.emoji');
            }
            if (emojiSpan && emojiSpan.classList.contains('emoji')) {
                if (input) {
                    input.value += emojiSpan.textContent;
                    input.focus();
                }
                panel.style.display = 'none';
            }
        }
        panel.addEventListener('click', handleEmojiSelect);
        panel.addEventListener('touchstart', handleEmojiSelect);
        document.addEventListener('click', function(e) {
            if (!panel.contains(e.target) && e.target !== btn) {
                panel.style.display = 'none';
            }
        });
    });

    console.log('DOMContentLoaded function finished (home)');
});

// Mesajları yükle
function loadMessages(room) {
    console.log('Loading messages for room:', room); // Debug log
    fetch(`/messages/${room}`)
        .then(response => {
            console.log('Load messages fetch response status:', response.status); // Debug log
            if (!response.ok) {
                // Hata durumunda JSON parse etmeden hatayı işle
                return response.json().then(err => { throw new Error(err.error || 'Unknown error'); });
            }
            return response.json();
        })
        .then(messages => {
            console.log(`Loaded ${messages.length} messages for room: ${room}`); // Debug log
            messageContainer.innerHTML = '';
            messages.forEach(message => {
                appendMessage(message);
            });
            scrollToBottom();
        })
        .catch(error => {
            console.error('Mesaj yükleme hatası:', error);
            // showError(`Mesajlar yüklenirken bir hata oluştu: ${error.message}`); // Base template'te varsa gerek yok
        });
}

// Mesajı ekrana ekle
function appendMessage(message) {
    console.log('Appending message:', message); // Debug log
    // Kapsayıcı satır
    const rowDiv = document.createElement('div');
    rowDiv.className = 'message-row';
    // Balon
    const bubbleDiv = document.createElement('div');
    bubbleDiv.className = 'message-bubble';
    bubbleDiv.textContent = message.content;
    // Balonun sadece içeriği kadar geniş olması için stil ekle
    bubbleDiv.style.display = 'inline-block';
    bubbleDiv.style.maxWidth = '60vw';
    bubbleDiv.style.minWidth = '40px';
    bubbleDiv.style.width = 'auto';
    bubbleDiv.style.boxSizing = 'border-box';
    // Kendi mesajı ise kırmızı, değilse gri
    const currentUserId = document.getElementById('global-chat').dataset.currentUserId;
    try {
        if (message.user_id != null && currentUserId != null && String(message.user_id) === String(currentUserId)) {
            bubbleDiv.style.background = '#900';
            bubbleDiv.style.color = '#fff';
    } else {
            bubbleDiv.style.background = '#23272b';
            bubbleDiv.style.color = '#fff';
        }
    } catch (e) {
        console.error('Mesaj balonu renk hatası:', e, message);
        bubbleDiv.style.background = '#23272b';
        bubbleDiv.style.color = '#fff';
    }
    rowDiv.appendChild(bubbleDiv);
    messageContainer.appendChild(rowDiv);
}

// Mesajları temizle
socket.on('clear_messages', function() {
    console.log('Clearing messages'); // Debug log
    messageContainer.innerHTML = '';
});

// En alta kaydır
function scrollToBottom() {
    if (messageContainer) { // Elementin varlığını kontrol et
        messageContainer.scrollTop = messageContainer.scrollHeight;
    } else {
        console.error('Message container element not found for scrolling!');
    }
}

// Sayfa yenilendiğinde veya kapatıldığında
window.addEventListener('beforeunload', function() {
    socket.emit('leave_room', { room: currentRoom }); // Global odadan ayrıl
});

// Yeni mesaj geldiğinde
socket.on('new_message', function(message) {
    console.log('Yeni mesaj alındı (home):', message); // Debug log
    if (message.room === currentRoom) {
        appendMessage(message);
        scrollToBottom();
        // Sistem mesajı ise ve türü connect/disconnect ise ilgili sesi çal
        if (message.is_system) {
            if (message.system_type === 'connect') {
                tryPlaySound(connectSound);
            } else if (message.system_type === 'disconnect') {
                tryPlaySound(disconnectSound);
            }
        } else {
            // Normal mesaj ise
            tryPlaySound(messageSound);
        }
    } else {
        console.log('Received message for different room:', message.room); // Debug log
    }
});

// Update the CSS styles
document.head.insertAdjacentHTML('beforeend', `
<style>
    .message {
        margin-bottom: 15px;
        display: flex;
        flex-direction: column;
        align-items: flex-start;
    }
    .message-header {
        display: flex;
        align-items: center;
        margin-bottom: 5px;
        width: 100%;
    }
    .message-header img {
        width: 30px;
        height: 30px;
        border-radius: 50%;
        margin-right: 8px;
        object-fit: cover;
    }
    .message-role {
        font-size: 0.85em;
        font-weight: bold;
        margin-right: 8px;
        color: #007bff;
    }
    .message-username {
        font-weight: bold;
        margin-right: 8px;
    }
    .message-content {
        margin-left: 38px;
        word-break: break-word;
        background-color: #2d2d2d;
        padding: 10px 15px;
        border-radius: 10px;
        color: white;
        max-width: 70%;
    }
</style>
`);