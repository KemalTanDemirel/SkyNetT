document.addEventListener('DOMContentLoaded', function() {
    // Form validation for registration
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        const password = document.getElementById('password');
        const confirmPassword = document.getElementById('confirmPassword');
        const passwordMatch = document.getElementById('passwordMatch');

        // Password match validation
        function validatePasswordMatch() {
            if (password.value && confirmPassword.value) {
                if (password.value === confirmPassword.value) {
                    confirmPassword.setCustomValidity('');
                    passwordMatch.textContent = 'Şifreler eşleşiyor';
                    passwordMatch.style.color = '#28a745';
                } else {
                    confirmPassword.setCustomValidity('Şifreler eşleşmiyor');
                    passwordMatch.textContent = 'Şifreler eşleşmiyor';
                    passwordMatch.style.color = '#dc3545';
                }
            }
        }

        password.addEventListener('input', validatePasswordMatch);
        confirmPassword.addEventListener('input', validatePasswordMatch);

        // Password strength validation
        password.addEventListener('input', function() {
            const value = this.value;
            let strength = 0;
            let feedback = [];

            if (value.length >= 8) strength++;
            else feedback.push('En az 8 karakter');

            if (/[A-Z]/.test(value)) strength++;
            else feedback.push('En az 1 büyük harf');

            if (/[a-z]/.test(value)) strength++;
            else feedback.push('En az 1 küçük harf');

            if (/[0-9]/.test(value)) strength++;
            else feedback.push('En az 1 rakam');

            if (strength < 4) {
                this.setCustomValidity(feedback.join(', '));
            } else {
                this.setCustomValidity('');
            }
        });

        // Username validation
        const username = document.querySelector('input[name="username"]');
        username.addEventListener('input', function() {
            const value = this.value;
            if (value.length < 3) {
                this.setCustomValidity('Kullanıcı adı en az 3 karakter olmalıdır');
            } else if (value.length > 20) {
                this.setCustomValidity('Kullanıcı adı en fazla 20 karakter olabilir');
            } else if (!/^[a-zA-Z0-9_]+$/.test(value)) {
                this.setCustomValidity('Kullanıcı adı sadece harf, rakam ve alt çizgi içerebilir');
            } else {
                this.setCustomValidity('');
            }
        });

        // Email validation
        const email = document.querySelector('input[name="email"]');
        email.addEventListener('input', function() {
            const value = this.value;
            if (!/^[a-zA-Z0-9._%+-]+@(gmail\.com|hotmail\.com|protonmail\.com)$/.test(value)) {
                this.setCustomValidity('Lütfen geçerli bir Gmail, Hotmail veya ProtonMail adresi girin');
            } else {
                this.setCustomValidity('');
            }
        });
    }

    // Form animations
    const inputs = document.querySelectorAll('.form-control');
    inputs.forEach(input => {
        input.addEventListener('focus', function() {
            this.parentElement.classList.add('focused');
        });

        input.addEventListener('blur', function() {
            if (!this.value) {
                this.parentElement.classList.remove('focused');
            }
        });
    });

    // Alert auto-dismiss
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });

    // Theme toggle (if available)
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            const body = document.body;
            const isDark = body.classList.contains('dark-theme');
            body.classList.toggle('dark-theme');
            body.classList.toggle('light-theme');
            this.innerHTML = isDark ? '<i class="fas fa-sun"></i>' : '<i class="fas fa-moon"></i>';
            
            // Save theme preference
            localStorage.setItem('theme', isDark ? 'light' : 'dark');
        });

        // Load saved theme
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme) {
            document.body.classList.remove('dark-theme', 'light-theme');
            document.body.classList.add(`${savedTheme}-theme`);
            themeToggle.innerHTML = savedTheme === 'dark' ? 
                '<i class="fas fa-moon"></i>' : 
                '<i class="fas fa-sun"></i>';
        }
    }

    // Form submission animation
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            if (this.checkValidity()) {
                const submitBtn = this.querySelector('button[type="submit"]');
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Yükleniyor...';
            }
        });
    });
}); 