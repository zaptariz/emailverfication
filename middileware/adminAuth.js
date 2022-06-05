
const jwt = require('jsonwebtoken')
const { usertoken } = require('../models/JwtToken')
const { model } = require('../models/userModel')


/*********************************
 * JsonWebToken For adminAuthenticaton.
 *
 * @param {string}      headers
 * @param {object}      id
 * @param {string}      userEmail
 * 
 * @returns {function}
 * 
 * 
 * note  : Jwt for feature works
 *********************************/
const adminAuth = async (req, res, next) => {
    try {
        let header = req.headers.authorization
        let verify_token = await jwt.verify(header, "secret")
        let check_token = await usertoken.findOne({ token: header, user: verify_token.id })
        if (!check_token && check_token.is_deleted) {
            throw new Error(" Token not found ")
        }
        else {
            let find_mail = await model.findOne({ userEmail: verify_token.userEmail })
            if (find_mail) {
                if (find_mail.role == 1) {
                    req.user = find_mail
                    next()
                }
                else throw new Error("Authentication failed. Your request could not be authenticated.")
            }
            else throw new Error("email id not found")
        }
    }
    catch (error) {
        return res.status(401).json(error.message);
    }
};

module.exports = adminAuth