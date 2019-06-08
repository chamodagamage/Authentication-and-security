//jshint esversion:6
require("dotenv").config();
const express = require ("express");
const ejs = require("ejs");
const bodyParser= require ("body-parser");
const mongoose = require ("mongoose");

//-------------packages require for creating session and cookie--------
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
//------------authenticate with google-----------------------------
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

//--------------authenticate with facebook-------------------------
const FacebookStrategy = require('passport-facebook').Strategy;

// --------hash encrypt using bcrypt--------------------
    // const bcrypt = require("bcrypt");
    // const saltRounds = 10;
// --------hash encrypt using md5--------------------
   //const md5 = require("md5");
// --------encrypt using a cncrypt key--------------------
   // const encrypt = require("mongoose-encryption");

const app = express();
app.use (bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));
app.set('view engine', 'ejs');

app.use(session({
  secret: 'this is our little secret.', //encryption key
  resave: false,
  saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());

//-------------------database connection--------------------------
mongoose.connect("mongodb://localhost:27017/secretUserDB", {useNewUrlParser:true});
mongoose.set("useCreateIndex", true);
const userSchema = new mongoose.Schema({
  email:String,
  password: String,
  googleId:String,
  facebookId:String,
  secret:String
});

// --------encrypt using a cncrypt key--------------------
      //userSchema.plugin(encrypt, { secret:process.env.SECRET , encryptedFields: ["password"] });
//-----------------------------------------------------------


userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//--------------------authenticate with google ----------------
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//--------------------authenticate with facebook----------------
passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({ facebookId: profile.id }, function(err, user) {
      if (err) { return done(err); }
      done(null, user);
    });
  }
));

//------------------------------get requests------------------------------------
app.get("/" , function(req, res){
  res.render("home.ejs");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
});

app.get("/auth/facebook",
  passport.authenticate("facebook")
);

app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", { successRedirect: "/secrets",
                                      failureRedirect: "/login" })
);

app.get("/login" , function(req, res){
  res.render("login.ejs");
});

app.get("/register" , function(req, res){
  res.render("register.ejs");
});

app.get("/secrets", function(req, res){
  User.find({"secret":{$ne:null}}, function(err, foundSecrets){
    if(foundSecrets){
      res.render("secrets",{userSecrets:foundSecrets})
    }
  });
});

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render("submit.ejs")
  }else{
    res.render("login.ejs");
  }
});
//-----------------------------------post requests----------------------
app.post("/register", function(req, res){
  User.register({username:req.body.username},req.body.password, function(err, user){
    if(err){
      res.render("login.ejs")
    }else{
      passport.authenticate("local")(req , res, function(){
        res.redirect("/secrets");
      });
    }
  });
  //password: md5(req.body.password) -- in md5
  //----------------bcrypt----------------------
            // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
            //   const newUser = new User({
            //     email: req.body.username,
            //     password: hash
            //   });
            //   newUser.save(function(err){
            //     if(err){
            //       console.log(err);
            //     }else{
            //       res.render("secrets");
            //     }
            //   });
            // });
  //----------------------------------------------------------
});

app.post("/login", function(req, res){
  const user = new User ({
    username:req.body.username,
    password : req.body.password
  });

  req.login(user, function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local")(req , res, function(){
        res.redirect("/secrets");
      });
    }
  });
  //-----------------------bcrypt---------------------------------
            // const username = req.body.username;
            // User.findOne({email:username}, function(err, foundUser){
            //   if(err){
            //     console.log(err);
            //   }else{
            //     bcrypt.compare(req.body.password, foundUser.password, function(err, result) {
            //       if(result===true){
            //         res.render("secrets");
            //       }
            //     });
            //   }
            // });
  //----------------------------------------------------------------
});

app.post("/submit", function(req, res){
  const newSecret= req.body.secret;
  User.findById(req.user.id, function(err, result){
    if (err){
      console.log(err);
    }else{
      if(result){
        result.secret = newSecret;
        result.save(function(err){
          if(!err){
            res.redirect("/secrets");
          }else{
            console.log();
          }
        });
      }
    }
  });
});
app.listen(3000, function(){
  console.log("server is running");
});
