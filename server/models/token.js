const mongoose = require('mongoose');
const Schema = mongoose.Schema
const tokenSchema = new Schema({
    token: "string"
})

const Token = mongoose.model("token", tokenSchema)
module.exports = Token;