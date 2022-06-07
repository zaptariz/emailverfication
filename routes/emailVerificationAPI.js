const express = require("express")
const api = require('../api/User')

const router = express.Router()

router.post('/signup',api.signup)
router.post('/verifyotp',api.verifyOtp)
router.post('/resendotp',api.resentOtp)
router.post('/signin',api.signin)
router.delete('/deleteuser',api.deleteUser)

module.exports = router