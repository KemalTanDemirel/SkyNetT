document.addEventListener('DOMContentLoaded', function() {
    const socket = io();
    let groupManagementModal = new bootstrap.Modal(document.getElementById('groupManagementModal'));

    // Group creation
    const createGroupForm = document.getElementById('create-group-form');
    if (createGroupForm) {
        createGroupForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const name = document.getElementById('group-name').value;
            const description = document.getElementById('group-description').value;
            const isPrivate = document.getElementById('is-private').checked;

            fetch('/create_group', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    name: name,
                    description: description,
                    is_private: isPrivate
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert(data.error || 'Grup oluşturulurken bir hata oluştu');
                }
            });
        });
    }

    // Join group
    document.querySelectorAll('.join-group').forEach(button => {
        button.addEventListener('click', function() {
            const groupId = this.dataset.groupId;
            fetch(`/group/${groupId}/join`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert(data.error || 'Gruba katılırken bir hata oluştu');
                }
            });
        });
    });

    // Request to join private group
    document.querySelectorAll('.request-join').forEach(button => {
        button.addEventListener('click', function() {
            const groupId = this.dataset.groupId;
            fetch(`/group/${groupId}/request_join`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Katılım isteğiniz gönderildi');
                    this.disabled = true;
                    this.innerHTML = '<i class="fas fa-clock"></i> İstek Gönderildi';
                } else {
                    alert(data.error || 'Katılım isteği gönderilirken bir hata oluştu');
                }
            });
        });
    });

    // Group management
    document.querySelectorAll('.manage-group').forEach(button => {
        button.addEventListener('click', function() {
            const groupId = this.dataset.groupId;
            fetch(`/group/${groupId}/management`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('group-management-content').innerHTML = data.html;
                        groupManagementModal.show();
                    } else {
                        alert(data.error || 'Grup yönetimi yüklenirken bir hata oluştu');
                    }
                });
        });
    });

    // Handle join requests (for group admins)
    function loadJoinRequests() {
        const requestsList = document.getElementById('join-requests-list');
        if (!requestsList) return;

        fetch('/group/join_requests')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    requestsList.innerHTML = data.requests.map(request => `
                        <div class="join-request-item mb-3">
                            <div class="d-flex justify-content-between align-items-center">
                                <div>
                                    <h6 class="mb-1">${request.username}</h6>
                                    <small class="text-muted">
                                        Grup: ${request.group_name}<br>
                                        İstek Tarihi: ${request.created_at}
                                    </small>
                                </div>
                                <div>
                                    <button class="btn btn-success btn-sm accept-request" data-request-id="${request.id}">
                                        <i class="fas fa-check"></i> Kabul Et
                                    </button>
                                    <button class="btn btn-danger btn-sm reject-request" data-request-id="${request.id}">
                                        <i class="fas fa-times"></i> Reddet
                                    </button>
                                </div>
                            </div>
                        </div>
                    `).join('');

                    // Update request count
                    document.getElementById('request-count').textContent = data.requests.length;

                    // Add event listeners for accept/reject buttons
                    document.querySelectorAll('.accept-request').forEach(button => {
                        button.addEventListener('click', handleRequestResponse('accept'));
                    });
                    document.querySelectorAll('.reject-request').forEach(button => {
                        button.addEventListener('click', handleRequestResponse('reject'));
                    });
                }
            });
    }

    function handleRequestResponse(action) {
        return function() {
            const requestId = this.dataset.requestId;
            fetch(`/group/join_request/${requestId}/${action}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    loadJoinRequests(); // Reload requests
                    if (action === 'accept') {
                        socket.emit('notification', {
                            user_id: data.user_id,
                            type: 'group_join_accepted',
                            content: `${data.group_name} grubuna katılım isteğiniz kabul edildi.`,
                            group_id: data.group_id
                        });
                    }
                } else {
                    alert(data.error || 'İşlem sırasında bir hata oluştu');
                }
            });
        };
    }

    // Group search
    const searchInput = document.getElementById('group-search');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            document.querySelectorAll('#available-groups-list .group-item').forEach(item => {
                const groupName = item.querySelector('h6').textContent.toLowerCase();
                const groupDesc = item.querySelector('small').textContent.toLowerCase();
                if (groupName.includes(searchTerm) || groupDesc.includes(searchTerm)) {
                    item.style.display = '';
                } else {
                    item.style.display = 'none';
                }
            });
        });
    }

    // Socket.IO notifications
    socket.on('notification', function(data) {
        // Show notification to user
        const notification = new Notification(data.content, {
            icon: '/static/images/logo.jpeg'
        });
        notification.show();

        // If it's a join request notification, reload the requests list
        if (data.type === 'group_join_request') {
            loadJoinRequests();
        }
    });

    // Initial load of join requests
    loadJoinRequests();
}); 