//required module
const mongoose = require('mongoose')

//Schema for login Token
const token = mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'user'
    },
    token: {
        type: String,
        index: true
    },
    is_deleted: {
        type: Boolean,
        default: false
    }
})

//create a model
const usertoken = new mongoose.model('usertoken', token)

//export the model
exports.usertoken = usertoken