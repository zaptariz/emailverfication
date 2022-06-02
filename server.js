const mongoose = require('mongoose')
const express = require('express')
const cors = require('cors')
const app = express()
app.use(express.json())
app.use(cors())
const dbconnection = () => {
    mongoose.connect('mongodb://localhost/emailverification')
    console.log("db connected")
}
dbconnection()

const router = require('./api/User');

app.use('/user',router)

app.listen(6566,() =>{
    console.log(" Node server connected")
})