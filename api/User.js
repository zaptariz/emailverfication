const express = require('express')
const usermodel = require('../models/userModel')
const nodemailer = require('nodemailer')
const bcrypt = require('bcrypt')
const otp_verification = require('../models/userOTPVerification')
const app = express()

const router = express.Router()

//NodeMailer stuff



router.post('/signup', async (req, res) => {
    try {
        const request = req.body
        //Check the user is exists
        let email_check = await usermodel.findOne({ userEmail: request.userEmail })
        if (!email_check) {
            req.body.password = await bcrypt.hash(req.body.password, 10)
            //insert to DB
            const response = await new usermodel(request).save()
                .then((result) => {
                    console.log("message will print")
                    sendOTPVerification(result, res)
                })
            return res.status(200).json(response)
        } else res.status(400).send(' Email already registered ')

    } catch (error) {
        res.status(401).json({ 'message ': error.message })
    }

})
router.post('/signin', async (req, res) => {
    try {
        let email_check = await usermodel.findOne({ userEmail: req.body.userEmail})
        let email_password = email_check.password
        if (email_check) {
            //this password from request
            let pas_from_user = req.body.password
            // this password from DB
            let pas_fromm_db = email_password
            //encrypt the password and save to psswd_vald for validation purpose
            let psswd_vald = await bcrypt.compare(pas_from_user, pas_fromm_db);
            if (psswd_vald) {
                let payload = {
                    id: email_check._id,
                    email: email_check.email_id
                }
                let token = jwt.sign(payload, "secret")
                // console.log('payload : ',payload, token)
                let tokenPayload = {
                    user: email_check._id,
                    token: token
                }
                //save the tokan in usertoken
                await new usertoken(tokenPayload).save()
                res.status(200).json(tokenPayload)
                console.log("logged in Successfully ", tokenPayload.user)
            }
            else
                return res.status(400).json('credential not matched')
        }
        else
            return res.status(400).json('Email Id not found signup with your mail')
    }
    catch (error) {
        return res.status(404).send(error.message)
    }
})

const sendOTPVerification = async (req, res) => {
    try {
        let transpoter = nodemailer.createTransport({
            host: "smtp.gmail.com",
            auth: {
                user: process.env.SENDER,
                pass: process.env.AUTH_PASS
            }
        })

        //verify transpoter 
        transpoter.verify((error, success) => {
            if (error) {
                console.log(error)
            }
            else {
                console.log("ready for a message")
                console.log(success)
            }
        })
        const otp = (Math.floor(1000 + Math.random() * 9000))
        //mail options 
        const mailoption = {
            from: process.env.AUTH_EMAIL,
            to: req.body.email,
            subject: "verify your mail",
            html: '<p> this is your opt ${otp} otp is  going to expires in one hour </p>'
        }

        //hash the OTP 
        let hashedOTP = await bcrypt.hash(otp, 10);
        const otpVerification = new otp_verification({
            userid: __id,
            otp: hashedOTP,
            createdAt: Date.now(),
            expiresAt: Date.now() + 360000
        })
        await otpVerification.save()
        await transpoter.sendMail(mailoption)
        res.json({
            status: "Pending",
            message: "verification OTP mail send to given address",
            Date: {
                userid: __id,
                email
            }
        })
    }
    catch (error) {
        res.json({
            status: "Failed",
            message: error.message
        }
        )
    }
}

// router.post('/signup', async (req, res) => {

// })

module.exports = router