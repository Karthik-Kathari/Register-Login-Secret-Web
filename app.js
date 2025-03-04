require('dotenv').config(); // Load environment variables from the .env file
const express = require('express');
const mongoose = require("mongoose");
const bcrypt = require('bcryptjs');
const session = require('express-session'); // Import session module for user login tracking
const app = express();

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Use sessions to track login state
app.use(session({
  secret: process.env.SESSION_SECRET, // Use the secret from environment variable
  resave: false,
  saveUninitialized: true
}));

// MongoDB Connection URI using .env values
const dbURI = `mongodb+srv://karthikkathari74:KiZWEqmlcDGiDtu0@register-login-secret-w.2ikl2.mongodb.net/?retryWrites=true&w=majority&appName=Register-Login-Secret-Web`;

// Connect to MongoDB
mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log("Connected to MongoDB Atlas successfully!");
  })
  .catch((error) => {
    console.error("Error connecting to MongoDB:", error.message); // Log detailed error
  });

// Define User Schema for registration and login
const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

// Define Secret Schema for storing secrets, with reference to the user
const secretSchema = new mongoose.Schema({
  secret: String,  // The secret entered by the user
  userId: {
    type: mongoose.Schema.Types.ObjectId, // Reference to User model
    required: true,
    ref: "User"
  }
});

const User = mongoose.model("User", userSchema);
const Secret = mongoose.model("Secret", secretSchema);

// Home route
app.get("/", function(req, res) {
  res.render("home");
});

// Register route
app.post("/register", async function(req, res) {
  const { username, password } = req.body;

  console.log("Attempting to register with username:", username); // Log the incoming data

  try {
    // Check if user with the same email already exists
    const existingUser = await User.findOne({ email: username });
    if (existingUser) {
      return res.send('This email is already registered. Please <a href="/login">login</a>.');
    }

    console.log("No existing user found, proceeding with registration...");

    // Hash the password before saving it
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log("Hashed password:", hashedPassword);  // Log hashed password (for debugging)

    // Create and save new user if no existing user
    const newUser = new User({
      email: username,
      password: hashedPassword
    });

    await newUser.save();  // Save user to the database
    console.log("New user saved:", newUser);  // Log the saved user object

    res.redirect("/login");  // Redirect to login page

  } catch (err) {
    console.error("Error during registration:", err); // Log detailed error
    res.status(500).send(`Error during registration: ${err.message}`); // Return the error message to the user
  }
});

// Login route
app.post("/login", async function(req, res) {
  const username = req.body.username;
  const password = req.body.password;

  console.log("Login attempt with username:", username);  // Log the incoming data

  try {
    const foundUser = await User.findOne({ email: username });

    if (foundUser) {
      // Compare the entered password with the hashed password
      const match = await bcrypt.compare(password, foundUser.password);

      if (match) {
        // Store the userId in the session after successful login
        req.session.userId = foundUser._id;
        res.redirect("/submit");  // Redirect to submit secrets page
      } else {
        res.send("Incorrect password!");
      }
    } else {
      res.send("No user found with that email!");
    }

  } catch (err) {
    console.error("Error during login:", err); // Log detailed error
    res.status(500).send(`Error during login: ${err.message}`);
  }
});

// Login page
app.get("/login", function(req, res) {
  res.render("login");
});

// Register page
app.get("/register", function(req, res) {
  res.render("register");
});

// Logout route
app.get("/logout", function(req, res) {
  req.session.destroy((err) => {
    if (err) {
      console.log(err);
    }
    res.redirect("/"); // Redirect to home page
  });
});

// Submit a Secret page (GET request)
app.get("/submit", function(req, res) {
  if (!req.session.userId) {
    return res.redirect("/login"); // Ensure user is logged in before accessing this page
  }
  res.render("submit");
});

// Submit a Secret page (POST request)
app.post("/submit", async function(req, res) {
  if (!req.session.userId) {
    return res.redirect("/login"); // Ensure user is logged in before submitting a secret
  }

  const newSecret = new Secret({
    secret: req.body.secret,
    userId: req.session.userId  // Associate secret with the logged-in user
  });

  try {
    await newSecret.save();  // Save secret to the database
    res.redirect("/secrets");  // Redirect to the page that shows only the user's secrets
  } catch (err) {
    console.error("Error saving the secret:", err); // Log the error
    res.status(500).send("Error saving the secret.");
  }
});

// Show all secrets for the logged-in user
app.get("/secrets", async function(req, res) {
  if (!req.session.userId) {
    return res.redirect("/login"); // Ensure user is logged in before viewing secrets
  }

  try {
    // Fetch secrets only for the logged-in user
    const secrets = await Secret.find({ userId: req.session.userId }).exec();
    res.render("secrets", { secrets: secrets }); // Pass user's secrets to the view
  } catch (err) {
    console.error("Error fetching secrets:", err); // Log the error
    res.status(500).send("Error fetching secrets.");
  }
});

// Start the server
app.listen(8000, function() {
  console.log("Server started on port 8000");
});
