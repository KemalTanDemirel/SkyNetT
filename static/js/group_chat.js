document.addEventListener('DOMContentLoaded', function() {
    const socket = io();
    const messagesDiv = document.getElementById('chat-messages');
    const messageForm = document.getElementById('message-form');
    const messageInput = document.getElementById('message-input');

    // Template'ten gelen değişkenleri al
    const groupId = document.getElementById('chat-container').dataset.groupId;
    const currentUserId = document.getElementById('chat-container').dataset.currentUserId;
    // Role ve username gibi diğer bilgileri de data attribute olarak eklememiz gerekebilir.

    // Odaya katıl
    socket.emit('join_room', { room: `group_${groupId}` });

    // Mesajları yükle
    fetch(`/messages/group_${groupId}`)
        .then(response => response.json())
        .then(messages => {
            messages.forEach(message => addMessage(message));
            scrollToBottom();
        });

    // Mesaj gönderme
    function sendMessage() {
        const message = messageInput.value.trim();
        if (message) {
            console.log('Mesaj gönderiliyor:', {
                content: message,
                room: `group_${groupId}`
            });
            
            // Mesajı HTTP POST ile gönder
            fetch('/send_message', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `content=${encodeURIComponent(message)}&room=${encodeURIComponent(`group_${groupId}`)}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    console.log('Mesaj başarıyla gönderildi');
                    messageInput.value = '';
                } else {
                    console.error('Mesaj gönderme hatası:', data.error);
                    alert(data.error || 'Mesaj gönderilirken bir hata oluştu');
                }
            })
            .catch(error => {
                console.error('Mesaj gönderme hatası:', error);
                alert('Mesaj gönderilirken bir hata oluştu');
            });
        }
    }

    // Form submit
    messageForm.addEventListener('submit', function(e) {
        e.preventDefault();
        sendMessage();
    });

    // Enter tuşu ile mesaj gönderme
    messageInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });

    // Yeni mesaj alma
    socket.on('new_message', function(message) {
        if (message.room === `group_${groupId}`) {
            addMessage(message);
            scrollToBottom();
        }
    });

    // Mesaj ekleme fonksiyonu
    function addMessage(message) {
        console.log('Appending message:', message); // Debug log
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message'; // Remove sent/received classes
        messageDiv.dataset.messageId = message.id;

        // Create header with profile image, role, and username
        const headerHtml = `
            <div class="message-header">
                <img src="${message.profile_image_url || '/static/images/default.png'}" alt="Profil" class="profile-image">
                ${message.role ? `<span class="message-role">${message.role.toUpperCase()}</span>` : ''}
                <span class="message-username">${message.username}</span>
            </div>
            <div class="message-content">${message.content}</div>
        `;
        
        messageDiv.innerHTML = headerHtml;
        messagesDiv.appendChild(messageDiv);
    }

    // Otomatik kaydırma
    function scrollToBottom() {
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }

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
}); 