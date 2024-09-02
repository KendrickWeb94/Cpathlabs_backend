const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/Cpathlabs', {
   useNewUrlParser: true,
   useUnifiedTopology: true,
}).then(() => console.log('Connected to MongoDB at localhost:27017'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Import models
const User = require('./models/Users');

// Routes
app.get('/', (req, res) => {
   res.send('Backend is running');
});

// Sign-Up Route
app.post('/signup', async (req, res) => {
   const { name, email, password, country, state, city, address, phone } = req.body;

   try {
      // Check if user already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
         return res.status(400).json({ message: 'User already exists' });
      }

      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create new user
      const newUser = new User({
         name,
         email,
         password: hashedPassword,
         country,
         state,
         city,
         address,
         phone
      });

      const savedUser = await newUser.save();
      res.status(201).json(savedUser);
   } catch (error) {
      res.status(500).json({ message: error.message });
   }
});

// Login Route
app.post('/login', async (req, res) => {
   const { email, password } = req.body;

   try {
      // Check if user exists
      const user = await User.findOne({ email });
      if (!user) {
         return res.status(400).json({ message: 'User does not exist' });
      }

      // Validate password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
         return res.status(400).json({ message: 'Invalid password' });
      }

      // Generate JWT token
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

      res.status(200).json({ token });
   } catch (error) {
      res.status(500).json({ message: error.message });
   }
});

// Fetch User Profile Route
app.get('/profile', async (req, res) => {
   const token = req.headers.authorization.split(' ')[1];
   
   try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id);
      
      if (!user) {
         return res.status(404).json({ message: 'User not found' });
      }

      res.status(200).json(user);
   } catch (error) {
      res.status(401).json({ message: 'Unauthorized' });
   }
});

// Update User Profile Route
app.put('/profile', async (req, res) => {
   const token = req.headers.authorization.split(' ')[1];

   try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findByIdAndUpdate(decoded.id, req.body, { new: true });
      
      if (!user) {
         return res.status(404).json({ message: 'User not found' });
      }

      res.status(200).json(user);
   } catch (error) {
      res.status(401).json({ message: 'Unauthorized' });
   }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
