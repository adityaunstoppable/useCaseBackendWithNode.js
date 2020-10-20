const express = require("express")
const router = express.Router()

//import controller
const {signup , accountActivation , signin ,forgotPassword ,resetPassword ,googleLogin} = require("../controllers/auth")

//import validators
const { userSignupValidator , userSigninValidator , forgotPasswordValidator ,resetPasswordValidator  } = require("../validators/auth")

const {runValidation} = require("../validators")

router.post("/signup" , userSignupValidator , runValidation,  signup)
 
router.post("/signin" , userSigninValidator  ,signin)

router.post("/account-activation" ,accountActivation )

// forgot reset password routes

router.put("/forgot-password",forgotPasswordValidator,runValidation ,forgotPassword )

router.put("/reset-password",resetPasswordValidator,runValidation ,resetPassword )

//google and facebook
router.post("/google-login", googleLogin)


module.exports = router
