const {Schema, model} = require("mongoose");

const emailRegexp = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;

const userSchema = Schema({
    password: {
        type: String,
        minlenght: 6,
        required: [true, 'Password is required'],
      },
      email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        match: emailRegexp,
      },
      subscription: {
        type: String,
        enum: ["starter", "pro", "business"],
        default: "starter"
      },
      token: {
        type: String,
        default: null,
      },
      avatarURL: {
        type: String,
        required: true,
      },
      verify: {
        type: Boolean,
        default: false,
      },
      verificationCode: {
        type: String,
        default: "",
      }
}, {versionKey: false});

const User = model("user", userSchema); 

module.exports = User;
