const User = require('../models/user');
const jwt = require('jsonwebtoken');

const expressJWT = require("express-jwt")

// sendgrid
const sgMail = require('@sendgrid/mail');
const { resetPasswordValidator } = require('../validators/auth');
const _ = require("lodash")
const {OAuht2Client, OAuth2Client} = require("google-auth-library");
const { response } = require('express');
const passport = require('passport');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// exports.signup = (req, res) => {
//     // console.log('REQ BODY ON SIGNUP', req.body);
//     const { name, email, password } = req.body;

//     User.findOne({ email }).exec((err, user) => {
//         if (user) {
//             return res.status(400).json({
//                 error: 'Email is taken'
//             });
//         }
//     });

//     let newUser = new User({ name, email, password });

//     newUser.save((err, success) => {
//         if (err) {
//             console.log('SIGNUP ERROR', err);
//             return res.status(400).json({
//                 error: err
//             });
//         }
//         res.json({
//             message: 'Signup success! Please signin'
//         });
//     });
// };

exports.signup = (req, res) => {
    const { name, email, password } = req.body;
    User.findOne({ email }).exec((err, user) => {
        if (user) {
            return res.status(400).json({
                error: 'Email is taken'
            });
        }

        const token = jwt.sign({ name, email, password }, process.env.JWT_ACCOUNT_ACTIVATION, { expiresIn: '10m' });

        const emailData = {
            from: process.env.EMAIL_FROM,
            to: email,
            subject: `Account activation link`,
            html: `
                <h1>Please use the following link to activate your account</h1>
                <p>${process.env.CLIENT_URL}/auth/activate/${token}</p>
                <hr />
                <p>This email may contain sensetive information</p>
                <h1>E-Commerce wali site se Mail</h1>
                <p>${process.env.CLIENT_URL}</p>
            `
        };

        sgMail
            .send(emailData)
            .then(sent => {
                  console.log('SIGNUP EMAIL SENT', sent)
                return res.json({
                    message: `Email has been sent to ${email}. Follow the instruction to activate your account`
                 });
            })
            .catch(err => {
                console.log('SIGNUP EMAIL SENT ERROR', err)
                return res.json({
                    message: err.message
                });
            });
    });
};


exports.accountActivation =(req ,res) => {
const  {token} = req.body

if(token){
    jwt.verify(token , process.env.JWT_ACCOUNT_ACTIVATION ,function(err, decoded){
     if(err){
         console.log("JWT Verify in account act err" ,err)
        return res.status(401).json({
            error:"Expired link . Signup Again"
        })
        }
        
        const {name , email ,  password} =jwt.decode(token)

        const user = new User({name, email , password})
        user.save((err , user) => {
            if(err){
                console.log("Save user in account act err" ,err)
                return res.status(400).json({
                    error:"Error saving user in database. Try signup again"
                })
            
            }
              return res.json({
                  message:"Signup success . Please Signin"
              })     
       
        })
       })

}else{
    return res.json({
        message:"Something went wrong try again !!!"
    })     

}

}


exports.signin = (req, res) => {
    const {email , password} = req.body ;

    User.findOne({email}).exec((err ,user) => {
        if(err ||!user){
           return res.status(400).json({
                error:"User with that email does not exist. Please Signup" 
            })
        }
        //authenticate
        if(!user.authenticate(password)){
            return res.status(400).json({
                error:"Email and password do not match" 
            })
        }
//generate a token and sent to client
const token = jwt.sign({_id: user._id} ,process.env.JWT_SECRET, {expiresIn:"7d"})
const {_id , name , email , role} = user 

return res.json({
    token ,
    user:{_id , name , email , role}
})
    })

}

exports.requireSignin = expressJWT({
    secret:process.env.JWT_SECRET 
})

exports.adminMiddleware = (req, res, next) =>{
    User.findById({_id:req.user._id}).exec((err ,user) =>{
        if(err || !user){
            return res.status(400).json({
                error:"User not found"
            })
        }
if(user.role !== "1"){
    return res.status(400).json({
        error:"Admin Resource , Access Denied"
    })
}
req.profile = user;
next();
    })
}


exports.forgotPassword = (req ,res) => {
    const {email} =req.body
   User.findOne({email}, (err , user) =>{
       if(err ||!user){
           return res.status(400).json({
               error:"User with that email does not exist"
           })
       }

        const token = jwt.sign({_id:user._id , name:user.name}, process.env.JWT_RESET_PASSWORD, { expiresIn: '10m' });

        const emailData = {
            from: process.env.EMAIL_FROM,
            to: email,
            subject: `Password Reset link`,
            html: `
                <h1>Please use the following link to reset your password </h1>
                <p>${process.env.CLIENT_URL}/auth/password/reset/${token}</p>
                <hr />
                <p>This email may contain sensetive information</p>
                <p>${process.env.CLIENT_URL}</p>
            `
        };
            return user.updateOne({resetPasswordLink:token} ,(err ,success)=>{
                if(err){
                     console.log("reset pass link err", err)
                    return res.status(400).json({
                        error:"Database connection on user forgot request"
                    })
                }else{

         
                    sgMail
                    .send(emailData)
                    .then(sent => {
                          console.log('SIGNUP EMAIL SENT', sent)
                        return res.json({
                            message: `Email has been sent to ${email}. Follow the instruction to activate your account`
                         });
                    })
                    .catch(err => {
                        console.log('SIGNUP EMAIL SENT ERROR', err)
                        return res.json({
                            message: err.message
                        });
                    });
        
        
                }
            })

   })
}


exports.resetPassword =(req ,res) =>{

    const {resetPasswordLink ,newPassword} = req.body
  if(resetPasswordLink){
      jwt.verify(resetPasswordLink, process.env.JWT_RESET_PASSWORD, function(err, decoded){
          if(err){
            return res.status(400).json({
                error:"Expired link ,try again"
            })  
          }
          User.findOne({resetPasswordLink}, (err ,user)=>{
              if(err|| !user){
                  return res.status(400).json({
                      error:"Something went wrong. Try Later"
                  })
              }
              const updatedFields = {
                  password:newPassword,
                  resetPasswordLink:""
              }
              user = _.extend(user , updatedFields)
              user.save((err ,result)=>{
                  if(err){
                      
            return res.status(400).json({
                error:"Error resetting user password"
            })  
                  }

                  res.json({
                      message:`Great! now you can login with your new password`
                  })
              })
          })    
      })
  }  
}

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID)

exports.googleLogin = (req,res) =>{
const {idToken} =req.body

client.verifyIdToken({idToken, audience:process.env.GOOGLE_CLIENT_ID})
.then(response =>{
    const {email_verified ,name ,email} = response.payload
    if(email_verified){
        User.findOne({email}).exec((err,user)=>{
            if(user){
                const token = jwt.sign({_id:user._id} ,process.env.JWT_SECRET ,{expiresIn:"7d"})
                const {_id ,email ,name ,role } = user
                return res.json({
                    token,
                    user:{_id ,email ,name ,role}
                })
            }else{
                let password = email + process.env.JWT_SECRET
                user = new User({name ,email ,password})
                user.save((err ,data) => {
                    if(err){
                        console.log("Error Google login on User Save" , err)
                        return res.status(400).json({
                            error:"User Signup Failed with Google "
                        })
                    }
                    
                const token = jwt.sign({_id:data._id} ,process.env.JWT_SECRET ,{expiresIn:"7d"})
                const {_id ,email ,name ,role } = data
                return res.json({
                    token,
                    user:{_id ,email ,name ,role}
                })
                })
            }
        })
    }else{
        return res.status(400).json({
            error:"Google Login Failed"
        })
   
    }
})
}






