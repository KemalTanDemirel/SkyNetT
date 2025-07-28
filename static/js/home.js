document.addEventListener('DOMContentLoaded', function() {
    // Socket.IO connection
    const socket = io();
    let currentRoom = 'global';
    let notifications = [];

    // DOM Elements
    const messageInput = document.getElementById('messageInput');
    const sendMessageBtn = document.getElementById('sendMessageBtn');
    const chatMessages = document.getElementById('chatMessages');
    const themeToggle = document.getElementById('themeToggle');
    const addFriendBtn = document.getElementById('addFriendBtn');
    const notificationsBtn = document.getElementById('notificationsBtn');
    const chatItems = document.querySelectorAll('.chat-item');
    const friendList = document.getElementById('friendList');
    const defaultProfileImgUrl = document.body.dataset.defaultProfileImg;

    // Theme Toggle
    themeToggle.addEventListener('click', function() {
        const body = document.body;
        const isDark = body.classList.contains('dark-theme');
        body.classList.toggle('dark-theme');
        body.classList.toggle('light-theme');
        themeToggle.innerHTML = isDark ? '<i class="fas fa-sun"></i>' : '<i class="fas fa-moon"></i>';
        
        // Save theme preference
        fetch('/update-theme', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                theme: isDark ? 'light' : 'dark'
            })
        });
    });

    // Chat Room Switching
    chatItems.forEach(item => {
        item.addEventListener('click', function() {
            const room = this.dataset.room;
            if (room === currentRoom) return;

            // Leave current room
            socket.emit('leave_room', { room: currentRoom });
            chatItems.forEach(i => i.classList.remove('active'));
            
            // Join new room
            currentRoom = room;
            this.classList.add('active');
            socket.emit('join_room', { room: room });
            
            // Update chat title
            const chatTitle = this.textContent.trim();
            document.querySelector('.chat-title').textContent = chatTitle;
            
            // Clear messages and load new room messages
            chatMessages.innerHTML = '';
            loadRoomMessages(room);
        });
    });

    // Send Message
    function sendMessage() {
        const message = messageInput.value.trim();
        if (message) {
            socket.emit('send_message', {
                message: message,
                room: currentRoom
            });
            messageInput.value = '';
        }
    }

    sendMessageBtn.addEventListener('click', sendMessage);
    messageInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });

    // Receive Message
    socket.on('new_message', function(data) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message';
        // Anonim mesajlar için farklı avatar ve kullanıcı adı
        const avatarUrl = data.is_anonymous ? data.profile_image_url : (data.profile_image_url ? data.profile_image_url : defaultProfileImgUrl);
        const usernameDisplay = data.is_anonymous ? data.username : `${data.username}:`;

        messageDiv.innerHTML = `
            <div class="message-header">
                 <img src="${avatarUrl}" alt="Profil Resmi" class="message-profile-img">
                <span class="message-username">${usernameDisplay}</span>
                <span class="message-time">${data.timestamp}</span>
            </div>
            <div class="message-content">${data.content}</div>
            <div class="message-actions">
                <button class="report-btn" onclick="reportMessage(${data.id})">
                    <i class="fas fa-ellipsis-v"></i>
                </button>
            </div>
        `;
        chatMessages.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    });

    // DM mesajı geldiğinde (varsayım: new_dm event ile geliyor)
    socket.on('new_dm', function(data) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message';
        // [sticker] etiketi varsa görsel olarak göster
        let contentHtml = data.content;
        const stickerMatch = contentHtml.match(/^\[sticker\](.+)\[\/sticker\]$/);
        if (stickerMatch) {
            contentHtml = `<img src="${stickerMatch[1]}" alt="sticker" style="max-width:120px;max-height:120px;border-radius:10px;">`;
        }
        messageDiv.innerHTML = `
            <div class="message-header">
                <img src="${data.sender_profile}" alt="Profil" class="chat-user-avatar">
                <span class="message-username">${data.sender_username}</span>
                <span class="message-time">${data.timestamp}</span>
            </div>
            <div class="message-content">${contentHtml}</div>
        `;
        chatMessages.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    });

    // Friend System
    addFriendBtn.addEventListener('click', function() {
        const modal = new bootstrap.Modal(document.getElementById('addFriendModal'));
        modal.show();
    });

    document.getElementById('sendFriendRequest').addEventListener('click', function() {
        const username = document.getElementById('friendUsername').value.trim();
        if (username) {
            socket.emit('friend_request', { username: username });
            bootstrap.Modal.getInstance(document.getElementById('addFriendModal')).hide();
        }
    });

    socket.on('friend_request', function(data) {
        addNotification('friend_request', `${data.username} sent you a friend request`);
    });

    socket.on('friend_status_update', function(data) {
        updateFriendStatus(data.username, data.status);
    });

    // Notification System
    function addNotification(type, message) {
        notifications.unshift({ type, message, timestamp: new Date() });
        updateNotificationBadge();
        updateNotificationsList();
    }

    function updateNotificationBadge() {
        const badge = document.getElementById('notificationCount');
        badge.textContent = notifications.length;
        badge.style.display = notifications.length > 0 ? 'block' : 'none';
    }

    function updateNotificationsList() {
        const list = document.getElementById('notificationsList');
        list.innerHTML = notifications.map(notification => `
            <div class="notification-item">
                <div class="notification-content">${notification.message}</div>
                <div class="notification-time">${formatTime(notification.timestamp)}</div>
            </div>
        `).join('');
    }

    notificationsBtn.addEventListener('click', function() {
        const modal = new bootstrap.Modal(document.getElementById('notificationsModal'));
        modal.show();
    });

    // Message Reporting
    window.reportMessage = function(messageId) {
        if (confirm('Are you sure you want to report this message?')) {
            socket.emit('report_message', { messageId: messageId });
        }
    };

    socket.on('message_reported', function(data) {
        addNotification('report', `Message from ${data.username} has been reported`);
    });

    // Utility Functions
    function formatTime(date) {
        return new Date(date).toLocaleTimeString();
    }

    function loadRoomMessages(room) {
        fetch(`/messages/${room}`)
            .then(response => response.json())
            .then(messages => {
                chatMessages.innerHTML = '';
                // Mesajları ters sırada ekleyerek en yeninin en altta görünmesini sağla
                messages.reverse().forEach(message => {
                    const messageDiv = document.createElement('div');
                    messageDiv.className = 'message';
                    let contentHtml = message.content;
                    const stickerMatch = contentHtml.match(/^\[sticker\](.+)\[\/sticker\]$/);
                    if (stickerMatch) {
                        contentHtml = `<img src="${stickerMatch[1]}" alt="sticker" style="max-width:120px;max-height:120px;border-radius:10px;">`;
                    }
                    messageDiv.innerHTML = `
                        <div class="message-header">
                            <img src="${message.sender_profile || defaultProfileImgUrl}" alt="Profil" class="chat-user-avatar">
                            <span class="message-username">${message.sender_username || ''}</span>
                            <span class="message-time">${message.timestamp}</span>
                        </div>
                        <div class="message-content">${contentHtml}</div>
                    `;
                    chatMessages.appendChild(messageDiv);
                });
                chatMessages.scrollTop = chatMessages.scrollHeight; // En alta kaydır
            });
    }

    // Initial load
    loadRoomMessages(currentRoom);
}); 