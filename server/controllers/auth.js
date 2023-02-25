import bcrypt from "bcrypt"
import Jwt from "jsonwebtoken"
import User from "../models/User.js"

/* REGISTER USER */
// call to mongoose database needs to be async
// req is request body we get from the frontend
// res is reponse body we send back to frontend
export const register = async(req,res) =>{
    try{
        const {
            firstName,
            lastName,
            email,
            password,
            picturePath,
            friends,
            location,
            occupation
        }=req.body;

        const salt=await bcrypt.genSalt();
        const passwordHash=await bcrypt.hash(password,salt);

        const newUser= new User({
            firstName,
            lastName,
            email,
            password: passwordHash,
            picturePath,
            friends,
            location,
            occupation,
            viewedProfile:Math.floor(Math.random()*1000),
            impressions:Math.floor(Math.random()*1000)
        });
        const savedUser=await newUser.save();
        res.status(201).json(savedUser);
        // 201 means some data is created and sends back a json format
    }catch(err){
        res.status(500).json({error:err.message});
        // 500 means something went wrong
    }
}


/* LOGGING IN */
export const login = async(req,res)=>{
    try{
        const {email,password}=req.body;
        const user = await User.findOne({email:email})
        if(!user) return res.status(400).json({msg:"User does not exist"});

        const isMatch = await bcrypt.compare(password,user.password);
        if(!isMatch) return res.status(400).json({msg:"Invalid credentials"});

        const token=Jwt.sign({id:user._id},process.env.JWT_SECRET);
        delete user.password;

        res.status(200).json({token,user});
    } catch(err){
        res.status(500).json({error:err.message});    
    }
}