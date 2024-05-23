const express =require('express');
const app=express();
const cors= require('cors');
const cookieParser = require('cookie-parser');
app.use(cookieParser());
console.log("----Attempting to connect to MongoDB Atlas------");

require('dotenv').config();
// const { default: mongoose } = require('mongoose');
const User=require('./models/User.js');// for using module created in USer.js
const place =require('./models/Place.js');
const booking =require('./models/Booking.js');
const imagedownloader =require('image-downloader')
const jwt= require('jsonwebtoken');
// Define connection options
const mongoose = require('mongoose');

// Define connection options
const connectionOptions = {
    useNewUrlParser: true,
    useUnifiedTopology: true
};
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
app.use(bodyParser.json());
// Connect to MongoDB Atlas
mongoose.connect(process.env.mongo_URI, connectionOptions)
    .then(() => {
        console.log('Connected to MongoDB Atlas successfully!');
    })
    .catch((error) => {
        console.error('Error connecting to MongoDB:', error);
    });



const secret=process.env.secret_key;
const bcrypt = require('bcrypt');
const multer =require('multer');
const fs= require('fs'); // FOR RENAMING A FILE ON SERVER
app.use(express.json());
app.use('/uploads' , express.static(__dirname + '/uploads'));
// app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(cors({
    credentials:true,
    origin:'http://localhost:3000'  // IF ANY REQUEST COMING FROM THIS ENDPOINT THEN PLS PASS THAT
//     // origin:'https://127.0.0.1:5173'
}));
const port= process.env.PORT
app.get('/test',(req,res)=>{
    console.log("haa");
    res.json("ok tested ha");
    // res.send("ok");
})

// function getUserDataFromReq(req){
//   const {token} =req.cookies;
//   return new Promise((resolve,reject)=>{
//    jwt.verify(token, secret, {}, async (err, userdata) => {
//      if(err) throw err;
//      // return userdata;
//      resolve(userdata);
//    })
//   })
//  }

function getUserDataFromReq(req) {
  const token = req.cookies.token; // Extract the token from cookies

  return new Promise((resolve, reject) => {
    if (!token) {
      return reject(new Error('Token must be provided')); // Reject the promise if the token is missing
    }

    jwt.verify(token, secret, {}, (err, userdata) => {
      if (err) {
        return reject(err); // Reject the promise if verification fails
      }
      resolve(userdata); // Resolve the promise with the user data if verification succeeds
    });
  });
}




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



app.post('/register', async (req, res) => {
  const { name, email, password, phoneno } = req.body; // Destructure details coming from the form in the request body
  const salt = await bcrypt.genSalt(10);
  const newpassword = await bcrypt.hash(password, salt);
  try {
      const newUser = await User.create({
          name, email, password: newpassword, phoneno
      });
      // Log the newly created user
      // console.log("New user created:", newUser);
      // Send the newly created user to the client
      res.json(newUser);
  } catch (e) {
      // Log any error that occurs during user creation
      console.error("Error creating user:", e);
      // Send an error response to the client
      res.status(422).json(e);
  }
});

app.post('/send-email', async (req, res) => {
  const { name, email, message } = req.body;

  const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: email,
    to: process.env.EMAIL_USER,
    subject: `Contact form submission from travo-APP by ${name}`,
    text: message,
  };

  try {
    await transporter.sendMail(mailOptions);
    res.json({ message: 'Email sent successfully!' });
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).json({ message: 'Failed to send email. Please try again later.' });
  }
});




app.get('/profile', async (req, res) => {
  const { token } = req.cookies;
  if (token) {
      jwt.verify(token, secret, {}, async (err, userdata) => {
          if (err) {
              return res.status(500).json({ error: "Internal Server Error" });
          }
          try {
              const user = await User.findById(userdata.id);
              if (!user) {
                  return res.status(404).json({ error: "User not found" });
              }
              // Check if the user object is not null before destrcturing
              const { name, email, _id, phoneno } = user;
              res.json({ name, email, _id });
          } catch (error) {
              console.error("Profile retrieval error:", error);
              res.status(500).json({ error: "Internal Server Error" });
          }
      });
  } else {
      res.json(null);
  }
});


app.post("/logout",(req,res)=>{
    res.cookie('token', '').json(true)
})

//
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
      const user = await User.findOne({ email });
      if (!user) {
          return res.status(422).json({ error: "User not found with this email" });
      }

      const passwordCompare = await bcrypt.compareSync(password, user.password);
      if (!passwordCompare) {
          return res.status(422).json({ error: "Password is not correct" });
      }

      // If user and password are correct, generate a JWT token
      jwt.sign(
          { email: user.email, id: user._id },
          secret,
          {},
          (err, token) => {
              if (err) throw err;
              // Set the token in a cookie and send user details as JSON response
              res.cookie('token', token).json(user);
          }
      );
  } catch (err) {
      // Handle other errors, such as database errors or unexpected errors
      console.error("Login error:", err);
      res.status(500).json({ error: "Internal Server Error" });
  }
});





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
  
app.post('/bookings', async(req,res) =>{
  const userData=await getUserDataFromReq(req);
    const {
         place,
        checkIn,
        checkOut,
        bookingDate,
        noGuest,
        name,
        mobile,
        price,
        placeOwner,
    } =req.body;

    try{

      const newbooking = await booking.create({
        place,
        checkIn,
        checkOut,
        bookingDate,
        noGuest,
        name,
        mobile,
        price,
        placeOwner,
        user:userData.id,
        
      });
      res.json(newbooking);
      // console.log(newbooking)
    }
    catch(err)
    {
      res.json("error in booking place, please try again");
          console.log("error in booking place due to ",err);
    }
})



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

app.get('/my-Bookings', async (req, res) => {
  try {
      const userData = await getUserDataFromReq(req);
      // console.log('UserData:', userData); // Debug log
      const bookings = await booking.find({ user: userData.id }).populate('place');
      // console.log('Bookings:', bookings); // Debug log
      res.json(bookings);
  } catch (error) {
      console.error('Error:', error); // Debug log
      res.status(401).json({ error: error.message });
  }
});
app.get('/BookingRequests', async (req, res) => {
  try {
      const userData = await getUserDataFromReq(req);
      // console.log('UserData:', userData); // Debug log
      const bookings = await booking.find({ placeOwner: userData.id }).populate('place');
      // console.log('Bookings:', bookings); // Debug log
      res.json(bookings);
  } catch (error) {
      console.error('Error:', error); // Debug log
      res.status(401).json({ error: error.message });
  }
});

// const isAuthorized = (req, res, next) => {
//   // Example authorization logic
//   if (req.user && req.user.role === 'admin') {
//       next();
//   } else {
//       res.status(403).json({ message: 'Unauthorized' });
//   }
// };

// Apply middleware to the DELETE endpoint
// app.delete('/places/:id', async (req, res) => {
//   const { id } = req.params;
//   const requser=getUserDataFromReq(req);
//   const ogowner= await place.findById(id).owner;
//   try {
//     if(requser.id===ogowner)
//       {

//         const deletedPlace = await place.findByIdAndDelete(id);
//         if (!deletedPlace) {
//           return res.status(404).json({ message: 'Place not found' });
//         }
//         res.status(200).json({ message: 'Place deleted successfully' });
//       }
//       else 
//       res.status(400).json({ message: 'unauthorised', error });


//   } catch (error) {
//       res.status(500).json({ message: 'Failed to delete place', error });
//   }
// });

app.delete('/places/:id', async (req, res) => {
  const { id } = req.params;
  const requser = await getUserDataFromReq(req);
  // console.log("id is ",id);
  // console.log("user is  ", requser.id);

  try {
    const placeToDelete = await place.findById(id);

    if (!placeToDelete) {
      return res.status(404).json({ message: 'Place not found' });
    }

    const ogowner = placeToDelete.owner;

    
    if (requser.id !== ogowner.toString()) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    await place.findByIdAndDelete(id);
    res.status(200).json({ message: 'Place deleted successfully' });

  } catch (error) {
    res.status(500).json({ message: 'Failed to delete place here be', error });
  }
});
// Delete a booking by ID
app.delete('/acounts/myBooking/:id', async (req, res) => {
  try {
      const {id} = req.params;
      // const userId = req.user._id; // Assuming you have user information in req.user from your authentication middleware
      const user = await getUserDataFromReq(req);
      const Booking = await booking.findById(id);
      // console.log("booking id is ",id);
      // console.log("booking done by   ",user);

      if (!Booking) {
          return res.status(404).json({ message: 'Booking not found' });
      }

      if (Booking.user.toString() !== user.id.toString()) {
          return res.status(403).json({ message: 'You do not have permission to delete this booking' });
      }

      await booking.findByIdAndDelete(id);

      res.status(200).json({ message: 'Booking deleted successfully' });
  } catch (error) {
      console.error('Error deleting booking:', error);
      res.status(500).json({ message: 'Failed to delete booking' });
  }
});

app.delete('/BookingRequests/:id', async (req, res) => {
  const { id } = req.params;
  // const userId = req.user.id; // Assuming you have user information stored in req.user after authentication
  const userId = await getUserDataFromReq(req);
  // console.log("id  of booking is ", id);
  // console.log( "deleting req  is done by ", userId.id)
  try {
    
    // Find the booking by ID
    // Check if the booking exists
    const Booking = await booking.findById(id);
    if (!Booking) {
      return res.status(404).json({ message: 'Booking not found' });
    }
    
    // console.log( "place owner is  ", Booking.placeOwner)

      // Check if the authenticated user is the placeOwner
      if (Booking.placeOwner.toString() !== userId.id.toString()) {
          return res.status(403).json({ message: 'You are not authorized to delete this booking' });
      }

      // Delete the booking
      await booking.findByIdAndDelete(id);

      // Send a success response
      res.status(200).json({ message: 'Booking Request deleted successfully' });
  } catch (error) {
      // Handle errors
      console.error('Error deleting booking:', error);
      res.status(500).json({ message: 'Failed to delete booking', error });
  }
});

app.get('/all-places', async (req, res) => {
  try {
      const places = await place.find();
      res.json(places);
  } catch (error) {
      console.error('Error fetching places:', error);
      res.status(500).json({ error: 'Internal Server Error' });
  }
});

  app.get('/acounts/myBooking/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const Booking = await booking.findById(id).populate('place');
        if (!Booking) {
            return res.status(404).json({ error: 'Booking not found' });
        }
        res.json(Booking);
    } catch (err) {
        console.error('Error fetching booking:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/places/:id',async  (req,res) =>{
    // res.json(req.params);
    const {id}= req.params;
    res.json(await place.findById(id));
})



// app.post('/profile-update/:id', async (req, res) => {
//     const { id } = req.params;
  
//     // Check if ID is valid
//     if (!mongoose.Types.ObjectId.isValid(id)) {
//       return res.status(400).json({ error: "Invalid ID" });
//     }
  
//     try {
//       const updatedDetails = await place.findByIdAndUpdate(id, {
//         title: req.body.title,
//         address: req.body.address,
//         description: req.body.description,
//         addedphotos: req.body.addedphotos,
//         perks: req.body.perks,
//         extrainfo: req.body.extrainfo,
//         checkin: req.body.checkin,
//         checkout: req.body.checkout,
//         maxguest: req.body.maxguest,
//         price: req.body.price,
//       }, { new: true });
  
//       // Check if the document was found and updated successfully
//       if (!updatedDetails) {
//         return res.status(404).json({ error: "Document not found" });
//       }
  
//       res.status(200).json(updatedDetails);
//     } catch (error) {
//       console.error(error);
//       res.status(500).json({ error: "Internal Server Error", details: error.message });
//     }
//   });


// module.exports = router;

app.post('/profile-update/:id', async (req, res) => {
  const { id } = req.params;

  // Check if ID is valid
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ error: "Invalid ID" });
  }

  // Log the received data for debugging
  // console.log("Received Data:", req.body);

  try {
    const updatedDetails = await place.findByIdAndUpdate(id, {
      title: req.body.title,
      address: req.body.address,
      description: req.body.description,
      photos: req.body.addedphotos, // Ensure this matches the schema type
      perks: req.body.perks,
      extrainfo: req.body.extrainfo,
      checkin: req.body.checkin,
      checkout: req.body.checkout,
      maxguest: req.body.maxguest,
      price: req.body.price,
    }, { new: true });

    // Check if the document was found and updated successfully
    if (!updatedDetails) {
      return res.status(404).json({ error: "Document not found" });
    }

    res.status(200).json(updatedDetails);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error", details: error.message });
  }
});

app.delete('/places/:id/photos/:photo', async (req, res) => {
  try {
    const { id, photo } = req.params;
    const place = await Place.findById(id);
    
    if (!place) {
      return res.status(404).json({ message: 'Place not found' });
    }

    place.photos = place.photos.filter(p => p !== photo);
    await place.save();

    res.json({ message: 'Photo deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting photo', error: err });
  }
});



app.listen(port,()=>{
    console.log("my app is listening on  port  ", port)
});

