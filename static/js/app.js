// Global utility functions for Secure Messaging System

// Show notifications
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}

// Format timestamp
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diffInHours = (now - date) / (1000 * 60 * 60);
    
    if (diffInHours < 24) {
        return date.toLocaleTimeString();
    } else {
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    }
}

// Validate message content
function validateMessage(message) {
    if (!message || message.trim().length === 0) {
        return { valid: false, error: 'Message cannot be empty' };
    }
    
    if (message.length > 500) {
        return { valid: false, error: 'Message too long (max 500 characters)' };
    }
    
    // Check for potentially harmful content
    const harmfulPatterns = [
        /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        /javascript:/gi,
        /on\w+\s*=/gi
    ];
    
    for (const pattern of harmfulPatterns) {
        if (pattern.test(message)) {
            return { valid: false, error: 'Message contains potentially harmful content' };
        }
    }
    
    return { valid: true };
}

// Sanitize user input
function sanitizeInput(input) {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
}

// Generate random ID
function generateId() {
    return Math.random().toString(36).substr(2, 9);
}

// Debounce function for performance
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Check if user is online
function isOnline() {
    return navigator.onLine;
}

// Handle offline/online events
window.addEventListener('online', function() {
    showNotification('Connection restored', 'success');
    if (typeof updateConnectionStatus === 'function') {
        updateConnectionStatus(true);
    }
});

window.addEventListener('offline', function() {
    showNotification('Connection lost. Please check your internet connection.', 'warning');
    if (typeof updateConnectionStatus === 'function') {
        updateConnectionStatus(false);
    }
});

// Security utilities
const SecurityUtils = {
    // Generate a secure random string
    generateSecureRandom: function(length = 32) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    },
    
    // Hash a string using SHA-256
    hashString: function(str) {
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        return crypto.subtle.digest('SHA-256', data)
            .then(hashBuffer => {
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            });
    },
    
    // Validate password strength
    validatePassword: function(password) {
        const minLength = 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
        
        const errors = [];
        
        if (password.length < minLength) {
            errors.push(`Password must be at least ${minLength} characters long`);
        }
        if (!hasUpperCase) {
            errors.push('Password must contain at least one uppercase letter');
        }
        if (!hasLowerCase) {
            errors.push('Password must contain at least one lowercase letter');
        }
        if (!hasNumbers) {
            errors.push('Password must contain at least one number');
        }
        if (!hasSpecialChar) {
            errors.push('Password must contain at least one special character');
        }
        
        return {
            valid: errors.length === 0,
            errors: errors,
            strength: this.calculatePasswordStrength(password)
        };
    },
    
    // Calculate password strength
    calculatePasswordStrength: function(password) {
        let score = 0;
        
        if (password.length >= 8) score += 1;
        if (password.length >= 12) score += 1;
        if (/[a-z]/.test(password)) score += 1;
        if (/[A-Z]/.test(password)) score += 1;
        if (/\d/.test(password)) score += 1;
        if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 1;
        
        if (score <= 2) return 'weak';
        if (score <= 4) return 'medium';
        if (score <= 5) return 'strong';
        return 'very-strong';
    }
};

// UI utilities
const UIUtils = {
    // Show loading spinner
    showLoading: function(element) {
        element.innerHTML = '<div class="loading"></div>';
        element.disabled = true;
    },
    
    // Hide loading spinner
    hideLoading: function(element, originalText) {
        element.innerHTML = originalText;
        element.disabled = false;
    },
    
    // Animate element
    animate: function(element, animation, duration = 1000) {
        element.style.animation = `${animation} ${duration}ms ease-in-out`;
        setTimeout(() => {
            element.style.animation = '';
        }, duration);
    },
    
    // Scroll to bottom of element
    scrollToBottom: function(element) {
        element.scrollTop = element.scrollHeight;
    },
    
    // Copy text to clipboard
    copyToClipboard: function(text) {
        navigator.clipboard.writeText(text)
            .then(() => {
                showNotification('Copied to clipboard', 'success');
            })
            .catch(err => {
                showNotification('Failed to copy to clipboard', 'error');
            });
    }
};

// Message utilities
const MessageUtils = {
    // Truncate long messages
    truncate: function(message, maxLength = 100) {
        if (message.length <= maxLength) return message;
        return message.substring(0, maxLength) + '...';
    },
    
    // Escape HTML entities
    escapeHtml: function(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, function(m) { return map[m]; });
    },
    
    // Format message for display
    formatMessage: function(message, sender, timestamp) {
        return {
            id: generateId(),
            content: this.escapeHtml(message),
            sender: this.escapeHtml(sender),
            timestamp: timestamp || new Date().toISOString(),
            formattedTime: formatTimestamp(timestamp || new Date().toISOString())
        };
    }
};

// Export utilities for use in other scripts
window.SecureMessagingUtils = {
    showNotification,
    formatTimestamp,
    validateMessage,
    sanitizeInput,
    generateId,
    debounce,
    isOnline,
    SecurityUtils,
    UIUtils,
    MessageUtils
}; 