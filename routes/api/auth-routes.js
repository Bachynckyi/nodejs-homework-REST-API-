const express = require('express');
const ctrl = require("../../controllers/auth-controllers.js");

const router = express.Router();

const authenticate = require("../../middlewares/authenticate.js");
const upload = require("../../middlewares/upload.js");

router.post("/users/register", ctrl.register);
router.post("/users/login", ctrl.login);
router.get("/users/current", authenticate, ctrl.getCurrent);
router.post("/users/logout", authenticate, ctrl.logout);
router.patch("/users", authenticate, ctrl.updateSubscription);
router.patch("/users/avatars", authenticate, upload.single("avatar"), ctrl.updateAvatar);
router.get("/users/verify/:verificationCode", ctrl.verify);
router.post("/users/verify/", ctrl.resendVerifyEmail);

module.exports = router;