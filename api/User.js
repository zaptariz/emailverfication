const express = require('express')
const usermodel = require('../models/userModel')
const nodemailer = require('nodemailer')
const transporter = require('../helper/nodeMailer')
const bcrypt = require('bcrypt')
const otp_verification = require('../models/userOTPVerification')
const sendOTPVerification = require("../helper/otpSender")
const jwt = require("jsonwebtoken")
const { usertoken } = require('../models/JwtToken')
require("dotenv").config()
const router = express.Router()

/*********************************
 * User signup.
 *
 * @param {string}      userName
 * @param {string}      userEmail
 * @param {string}      password
 * @param {boolean}     verified
 * 
 * @returns {function}
 *********************************/

router.post('/signup', async (req, res) => {
    try {
        const request = req.body
        //Check the user is exists
        let email_check = await usermodel.findOne({ userEmail: request.userEmail })
        if (!email_check) {
            req.body.password = await bcrypt.hash(req.body.password, 10)
            //insert to DB
            console.log()
            await usermodel(request).save()
                .then((result) => {
                    sendOTPVerification(result)
                    return res.status(200).json({ "id": result._id })
                }).catch(err => {
                    console.log("error  : ", err);
                })
        } else return res.status(400).send(' Email already registered ')

    } catch (error) {
        return res.status(401).json({ 'message ': error.message })
    }

})

/*********************************
 * User signup.
 *
 * @param {string}      userEmail
 * @param {string}      password
 * 
 * @returns {function}
 *********************************/

router.post('/signin', async (req, res) => {
    try {
        //Checking for exsiting email
        let email_check = await usermodel.findOne({ userEmail: req.body.userEmail })

        //Password Validation 
        let email_password = email_check.password
        if (email_check) {
            //this password from request
            let pass_from_user = req.body.password
            // this password from DB
            let pass_fromm_db = email_password
            //encrypt the password and save to psswd_vald for validation purpose
            let psswd_vald = await bcrypt.compare(pass_from_user, pass_fromm_db);
            if (psswd_vald) {
                let payload = {
                    id: email_check._id,
                    email: email_check.email_id
                }
                let token = jwt.sign(payload, "secret")
                let tokenPayload = {
                    user: email_check._id,
                    token: token
                }
                //save the tokan in usertoken
                await new usertoken(tokenPayload).save();
                return res.status(200).json({ "logged in Successfully ": tokenPayload.token })
            }
            else
                return res.status(400).json({ 'error_messageg': 'credential not matched' })
        }
        else
            return res.status(400).json({ 'error_messageg': 'Email Id not found signup with your mail' })
    }
    catch (error) {
        return res.status(404).send(error.message)
    }
})

/*********************************
 * OTP verification.
 *
 * @param {string}      userId
 * @param {string}      OTP
 * 
 * @returns {function}
 * 
 *********************************/

router.get('/verifyotp', async (req, res) => {
    try {
        const { userId, otp } = req.body
        if (!userId || !otp) {
            throw Error("details are empty")
        }
        else {
            // Find the OTP for a UserId
            const otpRecord = await otp_verification.find({ userId })
            if (otpRecord.length == 0) {
                throw new Error(" OTP doesn't exist or its already verified ")
            }
            else {
                //Handling the OTP lifetime
                const { expiresAt } = otpRecord[0]
                const hashedOTP = otpRecord[0].otp
                if (expiresAt < Date.now()) {
                    // Remove the expired OTP from the record
                    await otp_verification.deleteMany({ _id: userId })
                    throw new Error(" otp expired, please try again")
                } else {
                    //Decrypte the OTP for Verification
                    const validOtp = await bcrypt.compare(otp, hashedOTP)
                    //If OTP is not matched 
                    if (!validOtp) {
                        throw new Error(" invalid otp passed, check your otp ")
                    } else {
                        //If OTP verified then mark user as a verified user
                        await usermodel.updateOne({ _id: userId }, { verified: true })
                        // Remove the OTP records against verified users
                        await otp_verification.deleteMany({ userId })
                        //Find the user details for sending success mail
                        const find_mail = await usermodel.find({ userId })
                        const mailoption = {
                            from: process.env.SENDER,
                            to: find_mail[0].userEmail,
                            subject: "OTP verified Successful",
                            html: `welcome ${find_mail[0].userName} your mailId ${find_mail[0].userEmail} verified successfully `
                        }
                        //Mailer
                        transporter.sendMail(mailoption, (err, result) => {
                            if (err) {
                                return res.status(401).json('Opps error occured')
                            } else {
                                return res.status(200).json(result)
                            }
                        })
                        return res.status(200).send({
                            status: "verified",
                            message: 'your mailId verified successfully'
                        })
                    }
                }
            }
        }

    } catch (error) {
        console.log(error.message)
        return res.send({ status: " failed ", message: error.message })
    }
})

// OTP resend 
router.post('/resendotp', async (req, res) => {
    try {
        let { userId, userEmail } = req.body
        if (!userId || !userEmail) {
            throw Error("empty details are not accepted ")
        }
        else {
            //to delete the old OTP in record
            await otp_verification.deleteOne({ userId: userId })
            //Find the User Details for OTP resend 
            const UserID = await usermodel.findOne({ userId })
            if (!UserID.verified == true) {
                await usermodel.findOne({ userId })
                .then(result => {
                    sendOTPVerification(result)
                    console.log("\n\n\n result  : ", result)
                    return res.send({ " response ": " otp successfully resent " })
                }).catch(error => {
                    console.log(error)
                })
            }else return res.status(401).send({message: "emailId already verified"})
        }
    }
    catch (error) {
        return res.send({ " err message  ": error.message })
    }
})
module.exports = router