const transporter = require('./nodeMailer')
const bcrypt = require('bcrypt')
const otp_verification = require('../models/userOTPVerification')
/*********************************
 * Send OTP to Users
 *
 * @param {string}      Name
 * @param {string}      UserId
 * @param {string}      email
 * @param {string}      password
 * 
 * @returns {function}
 *********************************/

 const sendOTPVerification = async (result, res) => {
    try {
        // To create a 4 digit random number (OTP)
        const otp = `${(Math.floor(1000 + Math.random() * 9000))}`
        // Mail helper
        const mailoption = {
            from: process.env.SENDER,
            to: result.userEmail,
            subject: "verify your mail",
            html: `this is your otp : ${otp}, your OTP will expires with in one Hour`
        }
        //hash the OTP 
        let hashedOTP = await new bcrypt.hash(otp, 10)
        //Destructring OTP model
        const otpVerification = new otp_verification({
            userId: result._id,
            otp: hashedOTP,
            createdAt: Date.now(),
            expiresAt: Date.now() + 360000
        })
        // Save the OTP records for verification
        await otpVerification.save()
        // Send mail stuff
        transporter.sendMail(mailoption, (err, data) => {
            if (err) {
                // console.log(err)
                return res.status(401).json('Opps error occured')
            } else {
                return res.status(200).json(data)
            }
        })

    } catch (error) {
        console.log(error)
        return res.send({ "message ": error.message })
    }
}

module.exports = sendOTPVerification