import express from 'express'
import userAuth from '../middleware/userAuth.js';
import { getUserData } from '../controller/UserController.js';

const userRouter=express.Router();

userRouter.get('/data',userAuth,getUserData)

export default userRouter;