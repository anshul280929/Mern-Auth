import express from 'express'
import { isAthenticated, login, logout, passwordRestOtp, register, resetPassword, sendVerifyOtp, verifyEmail } from '../controller/AuthController.js';
import userAuth from '../middleware/userAuth.js';

const authRouter=express.Router();

authRouter.post('/register',register);
authRouter.post('/login',login);
authRouter.post('/logout',logout);
authRouter.post('/send-verify-otp',userAuth,sendVerifyOtp);
authRouter.post('/verify-account',userAuth,verifyEmail);
authRouter.get('/is-auth',userAuth,isAthenticated);
authRouter.post('/password-reset-otp',passwordRestOtp);
authRouter.post('/reset-password', resetPassword);

export default authRouter;
