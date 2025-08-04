import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../Models/userModel.js";
import transporter from "../config/nodemailer.js";
//User Register Function
export const register = async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.json({ success: false, message: "All fields are required" });
  }

  try {
    //Get user from the email
    const existingUser = await userModel.findOne({ email });
    //Check if user exist or not
    if (existingUser) {
      return res.json({ success: false, message: "User already exists" });
    }
    //Encrypt the password and save it
    const hashedPassword = await bcrypt.hash(password, 10);
    //Create user and save it in the database
    const user = new userModel({
      name,
      email,
      password: hashedPassword,
    });
    await user.save();
    //Generate token using jwt
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: '7d',
    }); 
    //send the token to user in resposnse via cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    //Sending welcome email
    const mailOptions={
        from: process.env.SENDER_EMAIL,
        to: email,
  subject: "Welcome to the Website",
  text: `Hello ${name}, welcome! Your account has been created with email: ${email}`,
  html: `<p>Hello <b>${name}</b>,</p><p>Welcome to our website! Your account has been created with <i>${email}</i>.</p>`,
    }

    await transporter.sendMail(mailOptions);

    return res.json({ success: true , message: "User registered successfully"});
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};
//Login Function
export const login = async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.json({ success: false, message: "All fields are required" });
  }

  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "Invalid Email" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.json({ success: false, message: "Invalid password" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: '7d',
    });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({ success: true });

  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

//Logout Function
export const logout = async (req, res) => {
    try{
        res.clearCookie("token", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        });

        return res.json({ success: true, message: "Logged out successfully" });

    }catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

//Send Verification OTP to the User's Email
export const sendVerifyOtp=async(req,res)=>{
    try{
        const {userId}=req.body;
        const user =await userModel.findById(userId);
        if(user.isAccountVerified){
            return res.json({success:false,message:"Account already verified"})
        }
        //Generate 6 digit OTP
        const otp=String(Math.floor(100000+Math.random()*900000))

        user.verifyOtp=otp;
        user.verifyOtpExpireAt= Date.now() + 24*60*60*1000 //Otp expires after 24 hours

        await user.save();

        const mailOption={
            from:process.env.SENDER_EMAIL,
            to:user.email,
            subject:'Account verification OTP',
            text: `Your OTP is ${otp}. Verify your account using this otp`
        }
        await transporter.sendMail(mailOption);
        return res.json({ success: true, message: 'Verification mail sent on mail' });
    }catch(error){
        res.json({success:false, message:error.message});
    }

}
//Verify email using Otp sent on email
export const verifyEmail= async (req,res)=>{
    const {userId,otp}=req.body;
    if(!userId||!otp){
        return res.json({success:false, message:'Missing details'})
    }
    try{
        //Find the user with the userId
        const user = await userModel.findById(userId);
        //If user is not found
        if(!user){
            return res.json({success:false, message:'User not found'})
        }
        //If Otp is wrong
        if(user.verifyOtp===""||user.verifyOtp!==otp){
            return res.json({success:false, message:'Invalid Otp'})
        }
        //If Otp is valid we'll check for expiry date
        if(user.verifyOtpExpireAt<Date.now()){
            return res.json({success:false, message:'Otp expires'})
        }
        //if otp is not expired, we'll check for user account
        user.isAccountVerified=true;
        //Refreshes the verifyotp
        user.verifyOtp="";
        user.verifyOtpExpireAt=0;

        //save the data in the database 
        await user.save();
        return res.json({success:true, message:'Email verified successfuly'})

    }catch(error){
        return res.json({success:false, message:error.message});
    }
}
//Check if user email is authenticated
export const isAthenticated= async(req,res)=>{
    try{
        return res.json({success:true});
    }
    catch(error){
        return res.json({success:false, message:error.message});
    }
}

//Send password rest otp
export const passwordRestOtp=async(req,res)=>{
    const {email}= req.body;
    if(!email){
        return res.json({success:false, message:'Email is required'});
    }
    try{
        const user=await userModel.findOne({email});
        if(!user){
            return res.json({success:false, message:'User not found'});
        }
        //Generate 6 digit OTP
        const otp=String(Math.floor(100000+Math.random()*900000))

        user.resetOtp=otp;
        user.resetOtpExpireAt= Date.now() + 15*60*1000 //Otp expires after 15 mins 

        await user.save();

        const mailOption={
            from:process.env.SENDER_EMAIL,
            to:user.email,
            subject:'Password rest otp',
            text: `Your OTP for reseting the password is ${otp}.Use this otp to reset your password`
        }
        await transporter.sendMail(mailOption);
        return res.json({success:true, message:'Otp sent to your email'});
    }
    catch(error){
        return res.json({success:false, message:error.message});
    }

}

//Rest user password using otp
export const resetPassword=async(req,res)=>{
    const {email,otp,newPassword}= req.body;
    if(!email || !otp || !newPassword){
        return res.json({success:false, message:'Missing details'});
    }
    try{
        const user=await userModel.findOne({email});
        if(!user){
             return res.json({success:false, message:'User not found'});
        }
        if(!user.resetOtp===""||user.resetOtp!==otp ){
             return res.json({success:false, message:'Invalid otp'});
        }
        if(user.resetOtpExpireAt<Date.now()){
             return res.json({success:false, message:'Otp expired'});
        }
        const hashedPassword=await bcrypt.hash(newPassword,10);

        user.password=hashedPassword;
        user.resetOtp="";
        user.resetOtpExpireAt=0;
        await user.save();
        return res.json({success:false, message:'Password has been saved successfully'});
    }
    catch(error){
        return res.json({success:false, message:error.message});
    }
}