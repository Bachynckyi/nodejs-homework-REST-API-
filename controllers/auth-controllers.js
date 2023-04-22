const Schemas = require("../Shemas/Shemas");
const {ctrlWrapper} = require("../utils/ctrlWrapper.js");
const User = require("../models/user-model.js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const gravatar = require("gravatar");
const fs = require("fs/promises");
const path = require("path");
const jimp = require('jimp');

const {SECRET_KEY} = process.env;
const avatarsDir = path.join(__dirname, "../", "public", "avatars");

const register = async(req, res) => {
    const {email, password} = req.body;
    const {error} = Schemas.registerSchema.validate(req.body);
    if (error) {
      return res.status(400).json({"message": "Ошибка от Joi или другой библиотеки валидации"});
    }
    const user = await User.findOne({email});
    if (user) {
      return res.status(409).json({"message": "Email in use"})
    };
    const hashPassword = await bcrypt.hash(password, 10);
    const avatarURL = gravatar.url(email);
    const result = await User.create({...req.body, password: hashPassword, avatarURL});
    res.status(201).json({
        email: result.email,
        subscription: "starter",
    });
};

const login = async(req, res) => {
    const {email, password} = req.body;
    const {error} = Schemas.registerSchema.validate(req.body);
    if (error) {
      return res.status(400).json({"message": "Ошибка от Joi или другой библиотеки валидации"});
    } 
    const user = await User.findOne({email});
    if (!user) {
        return res.status(401).json({"message": "Email or password is wrong"})
        
    };
    const passwordCompare = await bcrypt.compare(password, user.password);
    if(!passwordCompare){
        return res.status(401).json({"message": "Email or password is wrong"});
    }
    const payload = {
        id: user._id,
    };
    const token = jwt.sign(payload, SECRET_KEY, {expiresIn: "24h"});
    await User.findByIdAndUpdate(user._id, { token });
    res.json({token});
};

const getCurrent = async(req, res) => {
    const {email, subscription} = req.user;
    res.json({email, subscription});
};

const logout = async(req, res) => {
    const { _id } = req.user;
    await User.findByIdAndUpdate(_id, {token: ""});
    res.status(204).json()
};

const updateSubscription = async (req, res) => {
    const {error} = Schemas.updateSubscription.validate(req.body);
    if (error) {
      return res.status(400).json({"message": "Ошибка от Joi или другой библиотеки валидации"});
    } 
    const { _id } = req.user;
    await User.findByIdAndUpdate(_id, { subscription: req.body.subscription });
    res.status(200).json({"message": "Subsription updated"})
};

const updateAvatar = async (req, res) => {
    const {_id} = req.user; 
    const {path: tempUpload, filename} = req.file;
    const avatarName = `${_id}_${filename}`; 
    const resultUpload = path.join(avatarsDir, avatarName);
    await fs.rename(tempUpload, resultUpload);
    const imageAvatar = await jimp.read(resultUpload);
    await imageAvatar.resize(250, 250);
    await imageAvatar.writeAsync(resultUpload);
    const avatarURL = path.join("avatars", avatarName);
    await User.findByIdAndUpdate(_id, {avatarURL});
    res.status(200).json({avatarURL, "message": "Avatar updated"})
};

module.exports = {
    register: ctrlWrapper(register),
    login: ctrlWrapper(login),
    getCurrent: ctrlWrapper(getCurrent),
    logout: ctrlWrapper(logout),
    updateSubscription: ctrlWrapper(updateSubscription),
    updateAvatar: ctrlWrapper(updateAvatar),
};