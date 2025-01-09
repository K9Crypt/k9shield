const crypto = require('crypto');
const k9crypt = require('k9crypt');

class DataLossPreventionManager {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        
        this.sensitivePatterns = {
            creditCard: /\b(?:\d{4}[-\s]?){3}\d{4}\b/,
            email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
            ssn: /\b\d{3}-\d{2}-\d{4}\b/,
            phoneNumber: /\b\+?(\d{1,3}[-\s]?)?\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{4}\b/,
            iban: /\b[A-Z]{2}\d{2}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\b/,
            passport: /\b[A-Z]{1,3}\d{6,9}\b/
        };

        this.maskingOptions = {
            creditCard: (match) => this.maskCreditCard(match),
            email: (match) => this.maskEmail(match),
            ssn: (match) => this.maskSSN(match),
            phoneNumber: (match) => this.maskPhoneNumber(match),
            iban: (match) => this.maskIBAN(match),
            passport: (match) => this.maskPassport(match)
        };

        this.encryptionKey = this.generateEncryptionKey();
        this.encryptor = new k9crypt(this.encryptionKey);
    }

    scanForSensitiveData(data) {
        if (typeof data !== 'string') {
            data = JSON.stringify(data);
        }

        const detectedData = {};
        
        for (const [type, pattern] of Object.entries(this.sensitivePatterns)) {
            const matches = data.match(new RegExp(pattern, 'g')) || [];
            if (matches.length > 0) {
                detectedData[type] = matches;
                
                this.logger.log('warning', `Sensitive ${type} data detected`, {
                    count: matches.length,
                    pattern: pattern.toString()
                });
            }
        }

        return {
            hasSensitiveData: Object.keys(detectedData).length > 0,
            detectedData
        };
    }

    maskSensitiveData(data) {
        let processedData = data;

        if (typeof data !== 'string') {
            processedData = JSON.stringify(data);
        }

        for (const [type, pattern] of Object.entries(this.sensitivePatterns)) {
            processedData = processedData.replace(new RegExp(pattern, 'g'), (match) => {
                return this.maskingOptions[type](match);
            });
        }

        return typeof data === 'string' ? processedData : JSON.parse(processedData);
    }

    async encryptSensitiveData(data) {
        try {
            const dataString = typeof data === 'string' ? data : JSON.stringify(data);
            return await this.encryptor.encrypt(dataString);
        } catch (error) {
            this.logger.log('error', 'Encryption failed', { error: error.message });
            throw error;
        }
    }

    async decryptSensitiveData(encryptedData) {
        try {
            return await this.encryptor.decrypt(encryptedData);
        } catch (error) {
            this.logger.log('error', 'Decryption failed', { error: error.message });
            return null;
        }
    }

    maskCreditCard(cardNumber) {
        return cardNumber.slice(0, 4) + 
               '*'.repeat(cardNumber.length - 8) + 
               cardNumber.slice(-4);
    }

    maskEmail(email) {
        const [username, domain] = email.split('@');
        return username.slice(0, 2) + 
               '*'.repeat(username.length - 2) + 
               '@' + domain;
    }

    maskSSN(ssn) {
        return '***-**-' + ssn.slice(-4);
    }

    maskPhoneNumber(phoneNumber) {
        return phoneNumber.slice(0, 3) + 
               '*'.repeat(phoneNumber.length - 6) + 
               phoneNumber.slice(-3);
    }

    maskIBAN(iban) {
        return iban.slice(0, 4) + 
               '*'.repeat(iban.length - 8) + 
               iban.slice(-4);
    }

    maskPassport(passport) {
        return passport.slice(0, 2) + 
               '*'.repeat(passport.length - 4) + 
               passport.slice(-2);
    }

    generateEncryptionKey() {
        return crypto.randomBytes(32).toString('hex');
    }

    addCustomSensitivePattern(type, pattern) {
        if (!(pattern instanceof RegExp)) {
            throw new Error('Pattern must be a RegExp instance');
        }
        
        this.sensitivePatterns[type] = pattern;
        this.maskingOptions[type] = (match) => `[${type} MASKED]`;
        
        this.logger.log('info', `Custom sensitive pattern added for ${type}`);
    }
}

module.exports = DataLossPreventionManager; 