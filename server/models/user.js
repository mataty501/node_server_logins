const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const uniqueValidator = require("mongoose-unique-validator");
const userSchema = new Schema({
    email: {
        type: String,
        unique: true,
        match: /^([\w-\.]+@([\w-]+\.)+[\w-]{2,4})?$/,
        required: true,
    },
    password: {
        type: String,
        required: true,
    },
});
userSchema.plugin(uniqueValidator, { message: "user already exist." });
const User = mongoose.model("User", userSchema);
module.exports = User;