document.addEventListener('DOMContentLoaded', function() {
    const socket = io();
    const chatMessages = document.getElementById('chat-messages');
    const messageInput = document.getElementById('message-input');
    const sendMessageForm = document.getElementById('message-form');
    
    // Get the room name and current user ID from the chat-messages div data attributes
    const room = chatMessages.dataset.room;
    const currentUserId = parseInt(chatMessages.dataset.currentUserId);

    // Join the appropriate room
    if (room) {
        socket.emit('join_room', { room: room });
    }

    // Handle incoming messages
    socket.on('new_message', function(data) {
        appendMessage(data);
    });

    // Handle form submission
    if (sendMessageForm) {
        sendMessageForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const content = messageInput.value.trim();
            if (content && room) {
                // Send message and expect a callback response
                socket.emit('send_message', { room: room, content: content }, function(response) {
                    if (response && response.success === false) {
                        console.error('Message sending failed:', response.error);
                        // Optionally display an error message to the user
                        alert('Mesaj gönderilemedi: ' + response.error);
                    }
                });
                messageInput.value = ''; // Clear input after sending
            }
        });
    }
    
    // Handle Enter key to send message
    if (messageInput) {
        messageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault(); // Prevent newline
                sendMessageForm.dispatchEvent(new Event('submit')); // Trigger form submission
            }
        });
    }

    // Function to append a message to the chat window
    function appendMessage(data) {
        const messageDiv = document.createElement('div');
        messageDiv.classList.add('message');
        
        // Add 'sent' or 'received' class based on user ID
        if (data.user_id === currentUserId) {
            messageDiv.classList.add('sent');
        } else {
            messageDiv.classList.add('received');
        }

        // Mesaj içeriğinde sticker etiketi varsa görsel olarak göster
        let contentHtml = data.content;
        const stickerMatch = contentHtml.match(/^\[sticker\](.+)\[\/sticker\]$/);
        if (stickerMatch) {
            contentHtml = `<img src="${stickerMatch[1]}" alt="sticker" style="max-width:120px;max-height:120px;border-radius:10px;">`;
        }
        // Construct message HTML
        messageDiv.innerHTML = `
            <img src="${data.profile_image_url}" alt="Profile Image" class="message-avatar">
            <div class="message-content-wrapper">
                <div class="message-header">
                    <span class="message-role">${data.role}</span>
                    <span class="message-username">${data.username}</span>
                </div>
                <div class="message-content">${contentHtml}</div>
            </div>
        `;

        chatMessages.appendChild(messageDiv);
        // Auto-scroll to the bottom
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    // Initial message loading function
    function loadMessages() {
        if (room) {
            fetch(`/messages/${room}`)
                .then(response => response.json())
                .then(messages => {
                    // Clear existing messages before loading history
                    chatMessages.innerHTML = '';
                    messages.forEach(msg => appendMessage(msg));
                     // Scroll to the bottom after loading
                    chatMessages.scrollTop = chatMessages.scrollHeight;
                })
                .catch(error => {
                    console.error('Error loading messages:', error);
                });
        }
    }

    // Load initial messages when the script loads
    loadMessages();
}); 