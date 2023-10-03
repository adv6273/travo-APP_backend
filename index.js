const express =require('express');
const app=express();
const cors= require('cors');
const cookieParser = require('cookie-parser');
app.use(cookieParser());

require('dotenv').config();
const { default: mongoose } = require('mongoose');
const User=require('./models/User.js');// for using module created in USer.js
const place =require('./models/Place.js');
const imagedownloader =require('image-downloader')
const jwt= require('jsonwebtoken');
mongoose.connect(process.env.mongo_URL, { useNewUrlParser: true, useUnifiedTopology: true });
const secret=process.env.secret_key;
const bcrypt = require('bcrypt');
const multer =require('multer');
const fs= require('fs'); // FOR RENAMING A FILE ON SERVER
app.use(express.json());
app.use('/uploads' , express.static(__dirname + '/uploads'));
app.use(cors({
    credentials:true,
    origin:'http://localhost:3000'  // IF ANY REQUEST COMING FROM THIS ENDPOINT THEN PLS PASS THAT
//     // origin:'https://127.0.0.1:5173'
}));

app.get('/test',(req,res)=>{
    console.log("haa");
    res.json("ok tested ha");
    // res.send("ok");
})






// FOR SENDING USER DETAILS TO DATABASE
                               // AUTHENTICATION 
                               // AUTHENTICATION 
                               // AUTHENTICATION 
                               // AUTHENTICATION 
                               // AUTHENTICATION 
                               // AUTHENTICATION 
                               // AUTHENTICATION 
                               // AUTHENTICATION 
                               // AUTHENTICATION 

app.post('/register',async (req,res)=>{
    const {name,email,password,phoneno}=req.body; // for deconstructing details coming from the form in body
    const salt=await bcrypt.genSalt(10);
    const newpassword= await bcrypt.hash(password,salt);
    try
    {

        const newUser= await User.create({
            name,email,password : newpassword,phoneno
        }) 
        res.json(newUser); //  for sending user to database
        console.log(newUser);
    }
    catch(e){
        res.status(422).json(e);
        console.log("error : "+ e);
    }
})
app.get('/profile', async(req,res)=>{

    const {token}=  req.cookies;
    if(token)
    {
        jwt.verify(token, secret, {}, async (err,userdata)=>{
        const {name,email,_id,phoneno}= await  User.findById(userdata.id)
                if(err) throw err;
                res.json({name,email,_id});
        })

    }
    else{
        res.json(null);
    }

})
app.post("/logout",(req,res)=>{
    res.cookie('token', '').json(true)
})

app.post("/login", async(req,res)=>{
    const {email,password} =req.body;

    try{
        const user= await User.findOne({email});
        if(!user)
        {
            res.status(422).json({ error : "User not found with this email"});
            // res.status(422).json( "error User not found with this email");
        }
        else
        {
            // res.json("found");
            const passwordCompare= await bcrypt.compareSync(password,user.password);
            if(!passwordCompare)
            {
                res.status(422).json({Error :" Password is not correct "});
                alert("pass is worng");
            }
            else
            {

                jwt.sign
                (
                    {email:user.email, 
                        id: user._id
                    },
                    secret,{},
                    (err,token)=>
                    {
                         if(err) throw err;
                        res.cookie( 'token', token).json(user);
                    }
                );
                // res.status(200).json("login successfully");
            }
        }
     
    }
    catch(err)
    {
        res.status(400).json(err);
        // alert("login failed in index.js due to " + err);
    }
})





                                    ///     ADDING NEW PLACE TO DATABASE
                                    ///     ADDING NEW PLACE TO DATABASE
                                    ///     ADDING NEW PLACE TO DATABASE
                                    ///     ADDING NEW PLACE TO DATABASE
                                    ///     ADDING NEW PLACE TO DATABASE


app.post("/addingplace", async (req, res) => {
    const { token } = req.cookies;
    const {
      title,
      address,
      description,
      addedphotos,
      perks,
      extrainfo,
      checkin,
      checkout,
      maxguest,
      price,
    } = req.body;
  
    try {
      jwt.verify(token, secret, {}, async (err, userdata) => {
        if (err) throw err;
        
        try {
          const newplace = await place.create({
            owner: userdata.id,
            title,
            address,
            description,
            photos: addedphotos,
            perks,
            extrainfo,
            checkin,
            checkout,
            maxguest,
            price,
          });
  
          res.json(newplace);
          console.log(newplace);
        } catch (err) {
          res.json("error in adding place, please try again");
          console.log("not created new place due to this error ", err);
        }
      });
    } catch (err) {
      res.json("error in verifying token");
    }
  });
  


// console.log({__dirname})
app.post('/upload-by-link',async (req,res)=>{
    const {link} =req.body;
    // console.log(link);
    try{

        const newname= 'photo'+ Date.now()+'.jpg';
        // console.log("newname is : "+ newname + "  ");
        await imagedownloader.image({
            url:link,
            dest : __dirname + '/uploads/' + newname,
        });
        res.json( newname);
    }
    catch(err)
    {
        console.log(err + " err in upload by link")
        res.json("invalid link");
 
    }
})
const photomiddleware =multer({dest:'uploads/'});
app.post('/upload',photomiddleware.array('photos',100), async (req,res)=>{
    const uploadfiles=[];
    // console.log(req.files);    
    for(let i=0;i<req.files.length;i++)
    {
        const {path,originalname} = req.files[i];
        const parts= originalname.split('.');
        const ext=parts[parts.length-1];
        const newpath= path + "."+ ext;
        fs.renameSync(path,newpath);
        uploadfiles.push(newpath.replace('uploads\\',''));
    }
    res.json(uploadfiles);
        
});

app.get('/places', async (req,res)=>{
    const {token} =req.cookies;
    try {
        jwt.verify(token, secret, {}, async (err, userdata) => {
          if (err) throw err;
          
          try {
            const {id}=userdata;
            res.json(await place.find({owner:id}));
    
            
          } catch (err) {

            res.json("error in showing place, please try again");
            console.log("not showed places due to this error ", err);
          }
        });
      } catch (err) {
        res.json("error in verifying token");
      }
} )

app.listen(4000,()=>{
    console.log("my app is listening on  port 4000 ")
});

