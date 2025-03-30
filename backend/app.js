const express = require('express');
const jwt = require("jsonwebtoken");
const mongoose = require('mongoose');
const cors = require('cors');
const secretKey = "secretkey";
const bodyParser = require('body-parser');
const app = express();
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const ObjectId = mongoose.Types.ObjectId
app.use(bodyParser.json());
const MONGO_URI = 'mongodb://localhost:27017/imdb';


app.use(cors());
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.error('Error connecting to MongoDB:', error);
  });


//mongoose schema
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true,
  },
  userType:{
      type:String,
      required:true
  },
  name:{
      type:String,
      // required:true
  },
  phoneNumber:{
    type:String
  },
  profession:{
    type:String
  }
  // resetToken: String,                 // Reset token field
  // resetTokenExpiration: Date,
})

//mongoose model
const userData = mongoose.model('user', userSchema);


const adminSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true,
  },
  userType: { // Add userType field
    type: String,
    required: true // You can modify the required constraint as needed
  },
  name: {
    type: String,
    required: true
  },

  resetToken: String,                 // Reset token field
  resetTokenExpiration: Date,

  // verified: {
  //   type: Boolean,
  //   default: false
  // },
  // verificationToken: String, 
})

//mongoose model
const adminData = mongoose.model('admin', adminSchema);


app.post('/signup', async (req, res) => {

  const { email, password } = req.body;
  console.log('SignUp');
  const hashedPassword = await bcrypt.hash(password, 10)

  // const verificationToken = crypto.randomBytes(20).toString('hex');
  const newUser = new userData({
    email,
    password: hashedPassword,
    userType:'user'
  })
  try {
    await newUser.save();
    res.json({ message: 'Sign Up Successful' });
  }
  catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
})


app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await userData.findOne({ email });
    const admin = await adminData.findOne({ email });

    if (!user && !admin) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Determine the object (user or admin) and usertype
    let authObject;
    let usertype;

    if (user) {
      authObject = user;
      usertype = 'user';
    } else {
      authObject = admin;
      usertype = 'admin';
    }

    const isPasswordValid = await bcrypt.compare(password, authObject.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid Password' });
    }

    jwt.sign({ authObject }, secretKey, { expiresIn: '1800s' }, (err, token) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to generate token' });
      } else {
        console.log("Token generated:", token);
        // res.status(200).json({ token, userType: authObject.usertype, userId: authObject._id, email: authObject.email });
        console.log("User information");
        console.log(usertype)
        return res.json({ token, userType: usertype});
      }
    });

  } catch (error) {
    console.error('Internal server error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});


function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  if (typeof bearerHeader !== 'undefined') {
    const bearer = bearerHeader.split(' ');
    const token = bearer[1];
    req.token = token;
    console.log("Payload:", token)
    next();
  } else {
    res.status(401).json({ result: 'Invalid Token' });
  }
}

//Middleware function to verify the token
// Route to access the user's profile with token verification
app.post('/profile', verifyToken, (req, res) => {

  jwt.verify(req.token, secretKey, (err, authData) => {
    if (err) {
      res.status(403).json({ result: 'Invalid token' });
    } 
    else {
      const receivedToken = req.token; // Log the received token
      console.log('Received token:', receivedToken);
      res.json({
        message: 'Profile accessed',
        authData
      });
      console.log(authData);

    }
  });
});

//Middleware to regenerate the token
function regenerateToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  if (typeof bearerHeader !== 'undefined') {
    const bearer = bearerHeader.split(' ');
    const token = bearer[1];
    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        // Token has expired or is invalid, generate a new token
        const user = decoded?.user;
        if (user) {
          jwt.sign({ user }, secretKey, { expiresIn: '1800s' }, (err, newToken) => {
            if (err) {
              res.status(500).json({ error: 'Failed to generate token' });
            } else {
              req.token = newToken;
              next();
            }
          });
        } else {
          res.status(401).json({ result: 'Invalid Token' });
        }
      } else {
        req.token = token;
        next();
      }
    });
  } else {
    res.status(401).json({ result: 'Invalid Token' });
  }
}


function authenticateMiddleware(req, res, next) {
  const authorizationHeader = req.headers.authorization;
  console.log('Middleware execution started');
  if (typeof authorizationHeader !== 'undefined') {
    const tokenParts = authorizationHeader.split(' ');
    if (tokenParts.length !== 2 || tokenParts[0] !== 'bearer') {
      return res.status(401).json({ message: 'Invalid token format' });
    }   

    const token = tokenParts[1];

    jwt.verify(token, secretKey, (error, decodedToken) => {
      if (error) {
        return res.status(401).json({ message: 'Invalid token' });
      }
      req.user = decodedToken; // Set user data in request object
      console.log('Decoded user data:', req.user);

      next();
    });
  } else {
    res.status(401).json({ message: 'Authentication token missing' });
  }
}

// app.use('/dashboard', authenticateMiddleware);
async function updateUserInfoInDatabase(userId, newData) {
  try {
    // Construct the update object based on the filled fields in newData
    const updateObject = {};
    if (newData.name) {
      updateObject.name = newData.name;
    }
    if (newData.phoneNumber) {
      updateObject.phoneNumber = newData.phoneNumber;
    }
    if (newData.profession) {
      updateObject.profession = newData.profession;
    }

    // If there are no fields to update, return early
    if (Object.keys(updateObject).length === 0) {
      console.log('No fields to update.');
      return null;
    }

    // Find the user by ID and update the specified fields
    let updatedUser = await userData.findOneAndUpdate(
      { _id: new ObjectId(userId) },
      { $set: updateObject },
      { new: true } // Return the updated document
    );

    if (!updatedUser) {
      updatedUser = await adminData.findOneAndUpdate(
        { _id: new ObjectId(userId) },
        { $set: updateObject },
        { new: true } // Return the updated document
      );
    }

    // Log the updated user for debugging (optional)
    console.log('Updated user:', updatedUser);

    return updatedUser;
  } catch (error) {
    console.error('Error updating user info:', error);
    throw error; // Re-throw the error for handling in the calling function
  }
}



async function updatePassword(userId, newPassword){
  try{

    const hashedPassword = await bcrypt.hash(newPassword, 10); 

    let updatedUser= await adminData.findOneAndUpdate({
      _id:new ObjectId(userId)},
      {$set: { password:hashedPassword }},
      {new:true  }
    );
    if(!updatedUser){
      updatedUser=await userData.findOneAndUpdate(
        {_id: new ObjectId(userId)},
        { $set: { password: hashedPassword}},
        { new: true}
      );
    }
    console.log(updatedUser);
    return updatedUser;
  }
 catch(error) {
  console.error('Error updating user name:', error);
  throw error; // Re-throw the error for handling in the calling function
}}


app.get('/api/user', regenerateToken, authenticateMiddleware, async (req, res) => {

  const user = await getUserInfoFromDatabase(new ObjectId(req.user.authObject._id)); // Implement this function
  const admin = await getAdminInfoFromDatabase(new ObjectId(req.user.authObject._id)); // Implement this function

  if (user) {
    // account=user;
    res.json({ name: user.name, email: user.email, userType: "user", phoneNumber:user.phoneNumber,profession:user.profession });
  }

  else if (admin) {
    // account=admin;
    res.json({ name: admin.name, email: admin.email, userType: "admin", phoneNumber:admin.phoneNumber,profession:admin.profession }); // Return the admin's name
  }

  else {
    res.status(404).json({ message: 'User not found' });
  }
});


async function getUserInfoFromDatabase(loggedInUserId) {
  try {
    let user = await userData.findOne({ _id: new ObjectId(loggedInUserId) });

    // console.log('Retrieved user:', user);
    return user;

  } catch (error) {
    console.error('Error retrieving user information:', error);
    return null;
  }
}

async function getAdminInfoFromDatabase(loggedInAdminId) {
  try {
    // Assuming you have a model called AdminData
    const admin = await adminData.findOne({ _id: new ObjectId(loggedInAdminId) });
    // console.log('Retrieved admin:', admin);
    return admin;
  } catch (error) {
    console.error('Error retrieving admin information:', error);
    return null;
  }
}


// API to change Name
app.put('/api/updatename', regenerateToken, authenticateMiddleware, async (req, res) => {
  try {
    const userId = new ObjectId(req.user.authObject._id);
    const { newName,phoneNumber,profession } = req.body;

    console.log("new info received:", newName,phoneNumber,profession);

    // Update the user's name in the database
   // Update the user's information in the database
const updatedUser = await updateUserInfoInDatabase(userId, {
  name: newName,
  phoneNumber: phoneNumber,
  profession: profession,
});

    // Send the updated user information in the response
    res.json({ name: updatedUser.name, email: updatedUser.email, userType: updatedUser.userType ,phoneNumber:updatedUser.phoneNumber,profession:updatedUser.profession});
  } catch (error) {
    console.error('Error updating user name:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});


app.put('/api/updatePassword', regenerateToken, authenticateMiddleware, async (req, res) => {
  console.log("password changed");
  // const { email, password } = req.body;

  try {
    const userId = new ObjectId(req.user.authObject._id);
    const { oldPassword,newPassword } = req.body;

    const isPasswordValid = await bcrypt.compare(oldPassword,req.user.authObject.password)
  
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid old password.' });
    }
    // Update the user's name in the database
  await updatePassword(userId, newPassword);
    // Send the updated user information in the response
    res.json({ message: 'Password updated successfully.' });
  } catch (error) {
    console.error('Error updating user name:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});




// Define a function to generate the filename
function generateFilename(email) {
  return function(req, file, cb) {
    console.log("User Email:", email);

    if (!email) {
      return cb(new Error('User email not provided for saving image'));
    }

    cb(null, `${email}.jpg`); // Save the file with the email ID as its name
  };
}
// Multer storage configuration using the dynamically obtained email
const storage = multer.diskStorage({
  destination: './uploads/', // Specify the directory to save uploaded files
  filename: (req, file, callback) => {
    const userEmail = req.body.userId;
    callback(null, generateFilename(userEmail));
  },
});

const upload = multer({ storage: storage });

app.use(express.json());

app.post('/uploadProfilePicture', upload.single('file'), (req, res) => {
  // Retrieve the email from the request body
  const userEmail = req.body.userId;

  console.log("user email fetched in api:", userEmail);

  // Validate the email or perform other necessary checks
  if (!userEmail) {
    return res.status(400).json({ success: false, message: 'User email not provided' });
  }

  // The file has been successfully uploaded
  const profileImageUrl = `/uploads/${userEmail}.jpg`; // Assuming the files are stored in the 'uploads' directory

  // Save the profileImageUrl and userEmail in your database or handle as needed
  res.json({ success: true, profileImageUrl: profileImageUrl });
});




// Example endpoint to fetch profile picture URL
app.get('/fetchProfilePictureUrl/:email', (req, res) => {
  
  // Fetch the user's profile picture URL based on the provided email parameter
  const userEmail = req.params.email;

  console.log("name in get api",userEmail);
 
  // Assume the profile pictures are stored in the 'uploads' directory with filenames as email addresses
  const profileImageUrl = `/uploads/${userEmail}.jpg`; // Adjust the file extension based on your setup

  // Send the profileImageUrl as the response
  res.json({ profileImageUrl: profileImageUrl });

});



const port = 8020;
app.get('/', (req, res) => {
  res.send('Imdb Connected');
});

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});