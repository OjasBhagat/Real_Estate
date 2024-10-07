import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import prisma from "../lib/prisma.js";

export const register = async (req, res)=>{
    //db operations
    
    
    const {username , password , email} = req.body;
    try{
        const user = await prisma.user.findUnique({
            where : {username}
        })
    
        if(!user) return res.status(401).json({message:"Invalid credentials"})
    
        const hashsedPassword = await bcrypt.hash(password, 10);
        
        console.log(hashsedPassword);
        
        const newUser = await prisma.user.create({
            data : {
                username ,
                password : hashsedPassword ,
                email,
            }
        },
    );
    
    console.log(newUser);
    res.status(201).json({message:"User Created"})

}catch(err){
    console.log(err)
    res.status(500).json({message : "Failed to create user"})
}

}
export const login = async (req, res)=>{
    const {username , password} = req.body;

    try {
        // find user
        const user = await prisma.user.findUnique({
            where : {username}
        })

        if(!user) return res.status(401).json({message:"Invalid credentials"})

            //check password
        const isPassword = await bcrypt.compare(password , user.password);

        if(!isPassword) return res.status(401).json({message:"Invalid credentials"});
        
        //generate cookies JWT
        //res.setHeader("Set-Cookie" , "test=" + "myValue").json("success");  
        const age = 1000 * 60 * 60 * 24 * 7;

        const token = jwt.sign({
            id:user.id
        }, process.env.JWT_SECRET_KEY , {expiresIn:age} )

        const {}

        res.cookie("token" , token , {
            httpOnly:true,
            //secure:true
            maxAge:age,   
        }).status(200).json({message:"Login Successfull"})

    } catch (err) {
        console.log(err);
        res.status(500).json({message :"Failed to login!"});
        
        
    }
}
export const logout = (req, res)=>{
    res.clearCookie("token").status(200).json({message: "Logout successfull"});
}