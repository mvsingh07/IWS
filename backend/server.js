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
const fs = require('fs');
const ObjectId = mongoose.Types.ObjectId
app.use(bodyParser.json());
const MONGO_URI = 'mongodb://localhost:27017/imdb';

const router = express.Router();

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
    } 
    else {
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

// Token refresh endpoint
app.post('/refresh-token', async (req, res) => {
  // Extract the token from the request body
  const { token } = req.body;

  try {
    // Verify the token
    const decodedToken = jwt.verify(token, secretKey);

    // Extract user data from the decoded token
    const { authObject } = decodedToken;

    // Find the user in the database based on the extracted data
    let user;
    let admin;
    if (authObject && authObject._id) {
      user = await userData.findOne({ _id: new ObjectId(authObject._id) });
      admin = await adminData.findOne({ _id: new ObjectId(authObject._id) });
    }

    if(user){
    usertype = 'user';
    }

    if(admin){
    userType='admin';
    }

    if (!user && !admin) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Reissue a new token with the same user data and updated expiration time
    jwt.sign({ authObject }, secretKey, { expiresIn: '1800s' }, (err, newToken) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to generate new token' });
      } else {
        // Return the new token to the client
        return res.status(200).json({ newToken, userType: usertype });
      }
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    return res.status(401).json({ error: 'Invalid or expired token' });
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
    res.json({ id:user._id,name: user.name, email: user.email, userType: "user", phoneNumber:user.phoneNumber,profession:user.profession });
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

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function(req, file, cb) {
    cb(null, file.originalname );
  }
});

const upload = multer({ storage: storage });

app.post('/upload', upload.single('profilePicture'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('No files were uploaded.');
  }
  const imageUrl = `http://localhost:${port}/${req.file.path}`;
  res.json({ imageUrl });
});

app.post('/uploadDoc1', upload.single('doc1'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('No files were uploaded.');
  }
  const doc1Url = `http://localhost:${port}/${req.file.path}`;
  res.json({ doc1Url });
});


app.post('/uploadDoc2', upload.single('doc2'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('No files were uploaded.');
  }
  const doc2Url = `http://localhost:${port}/${req.file.path}`;
  res.json({ doc2Url });
});

app.post('/uploadDoc3', upload.single('doc3'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('No files were uploaded.');
  }
  const doc3Url = `http://localhost:${port}/${req.file.path}`;
  res.json({ doc3Url });
});

app.post('/uploadDoc4', upload.single('doc4'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('No files were uploaded.');
  }
  const doc4Url = `http://localhost:${port}/${req.file.path}`;
  res.json({ doc4Url });
});

app.post('/uploadDoc5', upload.single('doc5'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('No files were uploaded.');
  }
  const doc5Url = `http://localhost:${port}/${req.file.path}`;
  res.json({ doc5Url });
});

// Assuming uploads directory contains profile images
const uploadsDirectory = path.join(__dirname, 'uploads');


// API endpoint to serve profile images based on profileName
app.get('/profile-image/:profileName', (req, res) => {
  const profileName = req.params.profileName;
  
  // Construct the image file name with extension
  const imageName = `${profileName}.jpeg`; // Assuming all images have .jpg extension

  // Check if the image exists in the uploads directory
  const imagePath = path.join(uploadsDirectory, imageName);

  fs.access(imagePath, fs.constants.F_OK, (err) => {
    if (err) {
      // If the image doesn't exist, send a 404 response
      res.status(404).send('Image not found');
    } else {
      // If the image exists, send the URL to the image as a response
      res.sendFile(imagePath);
    }
  });
});

//api to get adhaar based on profile name
app.get('/profile-doc1/:profileName', (req, res) => {
  const profileName = req.params.profileName;
  
  // Read the files from the uploads directory
  fs.readdir(uploadsDirectory, (err, files) => {
    if (err) {
      // If there's an error reading the directory, send a 500 response
      res.status(500).send('Internal Server Error');
    } else {
      // Iterate through the files to find a match with the profileName
      let matchedFile = null;
      files.forEach((file) => {
        // Split the file name to remove the extension
        const fileNameWithoutExtension = file.split('.')[0];
        // Check if the profileName matches the fileNameWithoutExtension
        if (fileNameWithoutExtension === profileName) {
          matchedFile = file;
        }
      });

      if (matchedFile) {
        // If a matching file is found, send it to the frontend
        const imagePath = path.join(uploadsDirectory, matchedFile);
        res.sendFile(imagePath);
      } else {
        // If no matching file is found, send a 404 response
        res.status(404).send('Image not found');
      }
    }
  });
});

//api to get adhaar based on profile name
app.get('/profile-doc2/:profileName', (req, res) => {
  const profileName = req.params.profileName;
  
  // Read the files from the uploads directory
  fs.readdir(uploadsDirectory, (err, files) => {
    if (err) {
      // If there's an error reading the directory, send a 500 response
      res.status(500).send('Internal Server Error');
    } else {
      // Iterate through the files to find a match with the profileName
      let matchedFile = null;
      files.forEach((file) => {
        // Split the file name to remove the extension
        const fileNameWithoutExtension = file.split('.')[0];
        // Check if the profileName matches the fileNameWithoutExtension
        if (fileNameWithoutExtension === profileName) {
          matchedFile = file;
        }
      });

      if (matchedFile) {
        // If a matching file is found, send it to the frontend
        const imagePath = path.join(uploadsDirectory, matchedFile);
        res.sendFile(imagePath);
      } else {
        // If no matching file is found, send a 404 response
        res.status(404).send('Image not found');
      }
    }
  });
});

//api to get adhaar based on profile name
app.get('/profile-doc3/:profileName', (req, res) => {
  const profileName = req.params.profileName;
  
  // Read the files from the uploads directory
  fs.readdir(uploadsDirectory, (err, files) => {
    if (err) {
      // If there's an error reading the directory, send a 500 response
      res.status(500).send('Internal Server Error');
    } else {
      // Iterate through the files to find a match with the profileName
      let matchedFile = null;
      files.forEach((file) => {
        // Split the file name to remove the extension
        const fileNameWithoutExtension = file.split('.')[0];
        // Check if the profileName matches the fileNameWithoutExtension
        if (fileNameWithoutExtension === profileName) {
          matchedFile = file;
        }
      });

      if (matchedFile) {
        // If a matching file is found, send it to the frontend
        const imagePath = path.join(uploadsDirectory, matchedFile);
        res.sendFile(imagePath);
      } else {
        // If no matching file is found, send a 404 response
        res.status(404).send('Image not found');
      }
    }
  });
});

//api to get adhaar based on profile name
app.get('/profile-doc4/:profileName', (req, res) => {
  const profileName = req.params.profileName;
  
  // Read the files from the uploads directory
  fs.readdir(uploadsDirectory, (err, files) => {
    if (err) {
      // If there's an error reading the directory, send a 500 response
      res.status(500).send('Internal Server Error');
    } else {
      // Iterate through the files to find a match with the profileName
      let matchedFile = null;
      files.forEach((file) => {
        // Split the file name to remove the extension
        const fileNameWithoutExtension = file.split('.')[0];
        // Check if the profileName matches the fileNameWithoutExtension
        if (fileNameWithoutExtension === profileName) {
          matchedFile = file;
        }
      });

      if (matchedFile) {
        // If a matching file is found, send it to the frontend
        const imagePath = path.join(uploadsDirectory, matchedFile);
        res.sendFile(imagePath);
      } else {
        // If no matching file is found, send a 404 response
        res.status(404).send('Image not found');
      }
    }
  });
});

//api to get adhaar based on profile name
app.get('/profile-doc5/:profileName', (req, res) => {
  const profileName = req.params.profileName;
  
  // Read the files from the uploads directory
  fs.readdir(uploadsDirectory, (err, files) => {
    if (err) {
      // If there's an error reading the directory, send a 500 response
      res.status(500).send('Internal Server Error');
    } else {
      // Iterate through the files to find a match with the profileName
      let matchedFile = null;
      files.forEach((file) => {
        // Split the file name to remove the extension
        const fileNameWithoutExtension = file.split('.')[0];
        // Check if the profileName matches the fileNameWithoutExtension
        if (fileNameWithoutExtension === profileName) {
          matchedFile = file;
        }
      });

      if (matchedFile) {
        // If a matching file is found, send it to the frontend
        const imagePath = path.join(uploadsDirectory, matchedFile);
        res.sendFile(imagePath);
      } else {
        // If no matching file is found, send a 404 response
        res.status(404).send('Image not found');
      }
    }
  });
});


// Assuming uploads directory contains profile images
// const uploadsDirectory = path.join(__dirname, 'uploads');

// // API endpoint to serve profile images based on profileName
// app.get('/profile-image/:profileName', (req, res) => {
//   const profileName = req.params.profileName;

//   // Read the uploads directory
//   fs.readdir(uploadsDirectory, (err, files) => {
//     if (err) {
//       // If there's an error reading the directory, send a 500 response
//       res.status(500).send('Error reading directory');
//     } else {
//       // Find the file matching the profileName without extension
//       const matchingFile = files.find(file => {
//         const fileNameWithoutExtension = file.split('.')[0];
//         return fileNameWithoutExtension === profileName;
//       });

//       if (matchingFile) {
//         // If a matching file is found, send the file as a response
//         const filePath = path.join(uploadsDirectory, matchingFile);
//         res.sendFile(filePath);
//       } else {
//         // If no matching file is found, send a 404 response
//         res.status(404).send('Image not found');
//       }
//     }
//   });
// });



app.get('/uploadsList', (req, res) => {
  // Read the uploads directory
  fs.readdir(uploadsDirectory, (err, files) => {
    if (err) {
      // If there's an error reading the directory, send a 500 response
      res.status(500).send('Error reading directory');
    } else {
      // If successful, send the list of files as a response
      res.json({ files });
    }
  });
});











const port = 8020;
app.get('/', (req, res) => {
  res.send('Imdb Connected');
});

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});