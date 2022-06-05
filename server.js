const mongoose = require('mongoose')
const express = require('express')
const cors = require('cors')
const app = express()
app.use(express.json())

app.use(cors())
//Db connection options
const dbconnection = () => {
    mongoose.connect('mongodb://localhost/emailverification')
    console.log("db connected")
}

// DB connnection call
dbconnection()

//Routerr called
const router = require('./routes/emailVerificationAPI');

app.use('/user',router)

app.listen(6566,() =>{
    console.log(" Node server connected")
})