const mongoose = require('mongoose')

const email_verification = new mongoose.Schema({
    userName: {
        type: String,
        required: true
    },
    userEmail: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    verified: {
        type: Boolean
    }
})

const user = mongoose.model('user', email_verification)

module.exports = user