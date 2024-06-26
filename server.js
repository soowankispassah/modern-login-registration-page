require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;
const mongoURI = process.env.MONGO_URI;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Note: Set secure: true in production with HTTPS
}));

// Set EJS as the templating engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Connect to MongoDB
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log(err));

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    email: { type: String, unique: true },
    password: String,
    firstName: String,
    lastName: String,
    isVerified: { type: Boolean, default: false },
    verificationToken: String,
    verificationTokenExpires: Date,
    resetPasswordToken: String,
    resetPasswordExpires: Date
});

const User = mongoose.model('User', userSchema);

// Nodemailer setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Middleware to set user object for views
app.use((req, res, next) => {
    if (req.session.userId) {
        User.findById(req.session.userId, 'username', (err, user) => {
            if (err) {
                return next(err);
            }
            res.locals.user = user;
            next();
        });
    } else {
        res.locals.user = null;
        next();
    }
});

// Middleware to redirect logged-in users
function redirectIfLoggedIn(req, res, next) {
    if (req.session.userId) {
        return res.redirect('/profile');
    }
    next();
}

// Middleware to check if user is logged in
function checkAuth(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
}

// Serve Home Page
app.get('/', (req, res) => {
    res.render('index');
});

// Serve Login Page
app.get('/login', redirectIfLoggedIn, (req, res) => {
    res.render('login');
});

// Serve Register Page
app.get('/register', redirectIfLoggedIn, (req, res) => {
    res.render('register');
});

// Serve Profile Page
app.get('/profile', checkAuth, (req, res) => {
    res.render('profile');
});

// Serve Settings Page
app.get('/settings', checkAuth, (req, res) => {
    res.render('settings');
});

// Serve Reset Password Page
app.get('/reset-password', (req, res) => {
    res.render('reset-password');
});

// Register Route
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const usernameExists = await User.findOne({ username });
        if (usernameExists) {
            return res.status(400).send('Username already exists');
        }

        const emailExists = await User.findOne({ email });
        if (emailExists) {
            return res.status(400).send('Email already exists');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const verificationToken = crypto.randomBytes(20).toString('hex');
        const verificationTokenExpires = Date.now() + 3600000; // 1 hour

        const newUser = new User({
            username,
            email,
            password: hashedPassword,
            verificationToken,
            verificationTokenExpires
        });

        await newUser.save();

        const verificationLink = `http://localhost:${port}/verify-email?token=${verificationToken}`;

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Email Verification',
            text: `Please verify your email by clicking the following link: ${verificationLink}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return console.log(error);
            }
            console.log('Email sent: ' + info.response);
        });

        res.status(201).send('Registration successful! Please check your email to verify your account.');
    } catch (err) {
        res.status(500).send('Error registering user');
    }
});

// Verify Email Route
app.get('/verify-email', async (req, res) => {
    try {
        const { token } = req.query;
        const user = await User.findOne({ verificationToken: token, verificationTokenExpires: { $gt: Date.now() } });

        if (!user) {
            return res.status(400).send('Verification token is invalid or has expired');
        }

        user.isVerified = true;
        user.verificationToken = undefined;
        user.verificationTokenExpires = undefined;
        await user.save();

        req.session.userId = user._id; // Set the session user ID
        res.redirect(`/profile`);
    } catch (err) {
        res.status(500).send('Error verifying email');
    }
});

// Login Route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).send('User not found');
        }
        if (!user.isVerified) {
            return res.status(400).send('Email not verified. Please check your email.');
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send('Invalid credentials');
        }
        req.session.userId = user._id; // Save user ID in session
        res.redirect(`/`);
    } catch (err) {
        res.status(500).send('Error logging in user');
    }
});

// Fetch user data for profile
app.get('/profile-data', checkAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId, 'firstName lastName username email');
        if (!user) {
            return res.status(404).send('User not found');
        }
        res.json(user);
    } catch (err) {
        res.status(500).send('Error fetching user data');
    }
});

// Update user details
app.post('/update-details', checkAuth, async (req, res) => {
    const { username, firstName, lastName } = req.body;
    try {
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(404).send('User not found');
        }
        user.username = username;
        user.firstName = firstName;
        user.lastName = lastName;
        await user.save();
        res.send('Details updated successfully');
    } catch (err) {
        res.status(500).send('Error updating details');
    }
});

// Update user password
app.post('/update-password', checkAuth, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    try {
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(404).send('User not found');
        }
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).send('Incorrect current password');
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        await user.save();
        res.send('Password updated successfully');
    } catch (err) {
        res.status(500).send('Error updating password');
    }
});

// Delete user account
app.post('/delete-account', checkAuth, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.session.userId);
        req.session.destroy(err => {
            if (err) {
                return res.status(500).send('Error deleting account');
            }
            res.redirect('/');
        });
    } catch (err) {
        res.status(500).send('Error deleting account');
    }
});

// Logout Route
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Error logging out');
        }
        res.redirect('/');
    });
});

// Forgot Password Route
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).send('User not found');
        }

        const resetToken = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        const resetLink = `http://localhost:${port}/reset-password?token=${resetToken}`;

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset',
            text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
            Please click on the following link, or paste this into your browser to complete the process:\n\n
            ${resetLink}\n\n
            If you did not request this, please ignore this email and your password will remain unchanged.\n`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return console.log(error);
            }
            console.log('Email sent: ' + info.response);
        });

        res.send('Password reset link has been sent to your email.');
    } catch (err) {
        res.status(500).send('Error sending password reset email');
    }
});

// Reset Password Route
app.post('/reset-password', async (req, res) => {
    const { token, newPassword, confirmPassword } = req.body;
    try {
        if (newPassword !== confirmPassword) {
            return res.status(400).send('Passwords do not match');
        }

        const user = await User.findOne({ resetPasswordToken: token, resetPasswordExpires: { $gt: Date.now() } });

        if (!user) {
            return res.status(400).send('Password reset token is invalid or has expired');
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.redirect('/login'); // Redirect to the login page after successful password reset
    } catch (err) {
        res.status(500).send('Error resetting password');
    }
});

app.listen(port, () => console.log(`Server running on port ${port}`));
