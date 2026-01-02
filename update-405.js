const crypto = require('crypto');

class SecurityShieldAuth {
    /**
     * Simple authentication utility for security-shield-auth-374
     * @param {string} secret - The salt or secret key for hashing
     */
    constructor(secret = 'shield-default-374') {
        this.secret = secret;
    }

    hashPassword(password) {
        if (!password) throw new Error('Password is required');
        return crypto.createHmac('sha256', this.secret)
                     .update(password)
                     .digest('hex');
    }

    verify(password, hash) {
        const inputHash = this.hashPassword(password);
        return crypto.timingSafeEqual(Buffer.from(inputHash), Buffer.from(hash));
    }
}

module.exports = SecurityShieldAuth;