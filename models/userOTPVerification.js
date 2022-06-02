const mongoose = require('mongoose')

const OTP_verification = new mongoose.Schema({
    userId: {
        type: String
    },
    otp: {
        type: String
    },
    createdAt: {
        type: String
    },
    expiresAt: {
        type: String
    }
})

const otp_verify = mongoose.model('otp_verify',OTP_verification)

module.exports = otp_verify