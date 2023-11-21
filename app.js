require("dotenv").config();                             // adding .env file for secret variables
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption");      // adding level 2 encryption security
// const md5 = require("md5");                          // adding level 3 hashing security
// const bcrypt = require("bcrypt")                      // adding level 4 hashing and salting security
// const saltRounds = 10;                                // adding level 4 hashing and salting security
const session = require('express-session');                         // adding level 5 cookies and sessions security
const passport = require("passport");                               // adding level 5 cookies and sessions security
// do not have to add "const passportLocal = require('passport-local')" but have to 'npm install passport-local'
const passportLocalMongoose = require("passport-local-mongoose");   // adding level 5 cookies and sessions security
const FacebookStrategy = require('passport-facebook').Strategy;            // adding level 6 OAuth 2.0
const GoogleStrategy = require('passport-google-oauth20').Strategy;        // adding level 6 OAuth 2.0

const findOrCreate = require('mongoose-findorcreate');          // for findOrCreate method to work

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true}));

app.use(session({                           // adding level 5 cookies and sessions security
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());             // adding level 5 cookies and sessions security
app.use(passport.session());                // adding level 5 cookies and sessions security

const MONGODB_URI = process.env.MONGODB_URI;
mongoose.connect(MONGODB_URI);

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);   // adding level 5 cookies and sessions security
userSchema.plugin(findOrCreate);            // to make findOrCreate method work

// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });  // adding level 2 security - password encryption and using .env file

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());                // adding level 5 cookies and sessions security  

// passport.serializeUser(User.serializeUser());    // short version only for local authectication   // adding level 5 cookies and sessions security
// passport.deserializeUser(User.deserializeUser());   // short version only for local authentication   // adding level 5 cookies and sessions security

passport.serializeUser(function(user, cb) {         //works with any kind of authentication
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.displayName });
    });
  });
  
  passport.deserializeUser(function(user, cb) {         //works with any kind of authentication
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({                   // adding level 6 OAuth 2.0
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
},
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ username: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({                 // adding level 6 OAuth 2.0
    clientID: process.env.FB_APP_ID,
    clientSecret: process.env.FB_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ username: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
    res.render("home");
});

app.get("/auth/google", 
  passport.authenticate("google", { scope: ["profile"] }));   // adding level 6 OAuth 2.0

app.get("/auth/google/secrets",                                       // adding level 6 OAuth 2.0
  passport.authenticate("google", { failureRedirect: "/login" }),   
  function(req, res) {
    // Successful authentication, redirect to Secrets.
    res.redirect("/secrets");
  });

app.get("/auth/facebook",                   // adding level 6 OAuth 2.0
  passport.authenticate("facebook"));   

app.get('/auth/facebook/secrets',           // adding level 6 OAuth 2.0
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect Secrets.
    res.redirect("/secrets");
  });

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res){
    User.find({secret: {$ne:null}})
    .then(function(foundUsers){
        if (foundUsers) {
            res.render("secrets", {usersWithSecrets: foundUsers});
        };
    })
    .catch(function(err){
        console.log(err);
    });
});

app.get("/submit", function(req, res){
   if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    };  
});

app.get("/logout", function(req, res){
    req.logout(function(err){
        if (err) {
            console.log(err)
        };
    });
    res.redirect("/");
});

app.post("/register", function(req, res){
    
    User.register({username: req.body.username}, req.body.password, function (err, user){       // adding level 5 cookies and sessions security
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            })
        }
    })

    // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {     // Using level 4 security - hashing and salting  
    //     const newUser = new User ({
    //         username: req.body.username,
    //         password: hash
    //         //password: md5(req.body.password)            // Using level 3 security - hashing
    //     });
    //     newUser.save()
    //     .then(function(){
    //         console.log("New user was registered successfully!");
    //         res.render("secrets");
    //     })
    //     .catch(function(err){
    //         res.send(err);
    //     });
    // });
});

app.post("/login", function(req, res){
    
    currentUser = new User ({
        username: req.body.username,
        password: req.body.passport
    });
    
    req.login(currentUser, function(err){
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });    
        };
    });
    
    
    // const username = req.body.username;
    // const password = req.body.password;
    // //const password = md5(req.body.password);        // Using level 3 security - hashing

    // User.findOne({email: username})
    // .then(function(foundUser){
    //     if (foundUser) {
    //         //Using level 4 security use: if (foundUser.password === password){ ...}         
    //         bcrypt.compare(password, foundUser.password, function(err, result) {            // Using level 4 security - hashing and salting
    //             if (result === true) {
    //                 res.render("secrets");
    //             };
    //         });
    //     };
    // })
    // .catch(function(err){
    //     console.log(err);
    // });
});

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;

    User.findById(req.user.id)
    .then(function(foundUser){
        if (foundUser) {
            foundUser.secret = submittedSecret;
            foundUser.save()
            .then(
                res.redirect("/secrets")
            )
        };
    })
    .catch(function(err){
        console.log(err);
    })
})

app.listen(3000, function(){
    console.log("Server started on port 3000.");
});