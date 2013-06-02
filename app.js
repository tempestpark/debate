
var express=require("express"),passport=require("passport"),app=express(),LocalStrategy=require("passport-local").Strategy,mongodb=require("mongodb"),mongoose=require("mongoose"),bcrypt=require("bcrypt-nodejs"),SALT_WORK_FACTOR=10,http=require("http"),server=http.createServer(app),io=require("socket.io").listen(server),colors=require("colors");

if(require('os').platform() != 'win32') {
  var replify = require('replify');
  replify('realtime', app);
}

if(process.argv.indexOf('--dev') > -1) {
var open = require('open');
open('http://localhost:3000');
}


if(process.env.VCAP_SERVICES){
    var env = JSON.parse(process.env.VCAP_SERVICES);
    var mongo = env['mongodb-1.8'][0]['credentials'];
}
else{
    var mongo = {
        "hostname":"localhost",
        "port":27017,
        "username":"",
        "password":"",
        "name":"",
        "db":"db"
    };
}

var log = {
  log:function(d, l){
    if(l!='welcome') {
      if(!l){l='debug';}
      l=l.toUpperCase();
      l+=": ";
      if(l.toLowerCase()=='error'){l = l.red;}else{l=l.green;}
    }
    if(l == 'welcome'){l="";}
    process.stdout.write(l + d + '\n');
  }
};

log.log('Debate, by James Spencer, David Johns and Jackson Roberts; Copyright (c) 2013; MIT Licenced'.yellow, 'welcome');

//function to connect to production or local db
var generate_mongo_url = function(obj){
    obj.hostname = (obj.hostname || 'localhost');
    obj.port = (obj.port || 27017);
    obj.db = (obj.db || 'test');
    if(obj.username && obj.password){
        return "mongodb://" + obj.username + ":" + obj.password + "@" + obj.hostname + ":" + obj.port + "/" + obj.db;
    }
    else{
        return "mongodb://" + obj.hostname + ":" + obj.port + "/" + obj.db;
    }
};

if(require('fs').existsSync('config.js')) {
  var config = require('./config');
} else {
  var config = {
    mongo: {
      url: generate_mongo_url(mongo)
    }
  };
}

if(process.argv.indexOf('--port') > -1) {
  port = process.argv[process.argv.indexOf('--port') + 1];
}

var mongourl = config.mongo.url;

mongoose.connect(mongourl);
var db = mongoose.connection;
db.on('error', function(err) {
  var e = err.toString();
  log.log('DB Connection '.red + e.red, 'error');
});
db.once('open', function callback() {
  log.log('Mongoose: '.red  + 'Connected to DB'.green);
});

var port = process.env.VMC_APP_PORT || 4000;
if(process.argv.indexOf('-p') > -1) {
    port = process.argv[process.argv.indexOf('-p') + 1];
}

// User Schema
var userSchema = mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  location: {type: String,required:true},
  accessToken: { type: String } // Used for Remember Me
});

// Bcrypt middleware
userSchema.pre('save', function(next) {
    var user = this;

  if(!user.isModified('password')) return next();

  bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt) {
    if(err) return next(err);

    bcrypt.hash(user.password, salt,
    function() {
      //needed for some reason..?
    },
    function(err, hash) {
      if(err) return next(err);
      user.password = hash;
      next();
    });
  });
});

// Password verification
userSchema.methods.comparePassword = function(candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if(err) return cb(err);
    cb(null, isMatch);
  });
};

// Remember Me implementation helper method
userSchema.methods.generateRandomToken = function () {
  var user = this,
      chars = "_!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
      token = new Date().getTime() + '_';
  for ( var x = 0; x < 16; x++ ) {
    var i = Math.floor( Math.random() * 62 );
    token += chars.charAt( i );
  }
  return token;
};

// Seed a user
var User = mongoose.model('User', userSchema);

// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.
//
//   Both serializer and deserializer edited for Remember Me functionality
passport.serializeUser(function(user, done) {
  var createAccessToken = function () {
    var token = user.generateRandomToken();
    User.findOne( { accessToken: token }, function (err, existingUser) {
      if (err) { return done( err ); }
      if (existingUser) {
        createAccessToken(); // Run the function again - the token has to be unique!
      } else {
        user.set('accessToken', token);
        user.save( function (err) {
          if (err) return done(err);
          return done(null, user.get('accessToken'));
        });
      }
    });
  };

  if ( user._id ) {
    createAccessToken();
  }
});

passport.deserializeUser(function(token, done) {
  User.findOne( {accessToken: token } , function (err, user) {
    done(err, user);
  });
});


// Use the LocalStrategy within Passport.
//   Strategies in passport require a `verify` function, which accept
//   credentials (in this case, a username and password), and invoke a callback
//   with a user object.  In the real world, this would query a database;
//   however, in this example we are using a baked-in set of users.
passport.use(new LocalStrategy(function(username, password, done) {
  User.findOne({ username: username }, function(err, user) {
    if (err) { return done(err); }
    if (!user) { return done(null, false, { message: 'Unknown user ' + username }); }
    user.comparePassword(password, function(err, isMatch) {
      if (err) return done(err);
      if(isMatch) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Invalid password' });
      }
    });
  });
}));

function randStr(len) {
var pos = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';
var arr = pos.split('');
var out = '';
for(var i = 0; i < len; i++) {
out += arr[Math.floor(Math.random() * arr.length)];
}
return out;
}

// configure Express
app.configure(function() {
  app.set('views', __dirname + '/views');
  app.set('view engine', 'ejs');
  app.engine('ejs', require('ejs-locals'));
  app.use(express.logger('dev'));
  app.use(express.cookieParser());
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(express.session({ secret: 'keyboard cat' })); // CHANGE THIS SECRET!
  // Remember Me middleware
  app.use( function (req, res, next) {
    if ( req.method == 'POST' && req.url == '/login' ) {
      if ( req.body.rememberme ) {
        req.session.cookie.maxAge = 2592000000; // 30*24*60*60*1000 Rememeber me for 30 days
      } else {
        req.session.cookie.expires = false;
      }
    }
    next();
  });

    // Handle 500s
  app.use(function(error, req, res, next) {
    res.status(500);
    var upslashes = '';
    var no_slashes = req.url.split("/").length - 1;
    for(var i = 0; i < no_slashes; i++) {
      upslashes += '../';
    }
    res.render('500', {title:'500: Internal Server Error', error: error, upslashes: upslashes });
  });
  // Initialize Passport!  Also use passport.session() middleware, to support
  // persistent login sessions (recommended).
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(express.static(__dirname + '/public'));
  app.use(app.router);
});

// This maps urls to templates.
app.get('/', function(req, res){
  res.render('index', { user: req.user });
});

app.get('/account', ensureAuthenticated, function(req, res){
  res.render('account', { user: req.user });
});

app.get('/login', function(req, res){
  res.render('login', { user: req.user, message: req.session.messages });
  req.session.messages = null;
});

// POST /login
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
//
//   curl -v -d "username=bob&password=secret" http://127.0.0.1:3000/login
//   
/***** This version has a problem with flash messages
app.post('/login', 
  passport.authenticate('local', { failureRedirect: '/login', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  });
*/

// POST /login
//   This is an alternative implementation that uses a custom callback to
//   acheive the same functionality.
app.post('/login', function(req, res, next) {
  passport.authenticate('local', function(err, user, info) {
    if (err) { return next(err); }
    if (!user) {
      req.session.messages =  [info.message];
      return res.redirect('/login');
    }
    req.logIn(user, function(err) {
      if (err) { return next(err); }
      return res.redirect('/');
    });
  })(req, res, next);
});

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

app.get('/register', function(req, res){
  var taken = {username:false, email:false};
  if(req.param('err') == 2) {
    taken = {username:false, email:true,invalidEmail:false};
  } else if(req.param('err') == 3) {
    taken = {username:true, email:false,invalidEmail:false};
  } else if(req.param('err') == 5) {
    taken = {username:false, email:false,invalidEmail:true};
  }
    res.render('register', { user: req.user, message: req.session.messages, error:false, taken:taken });
});

app.post('/register', function(req, res) {
  var username = req.param('username');
  var password = req.param('password');
  var email = req.param('email');
if(username === null || password === null || email === null || username === "" || password === "" || email === "") {
    res.redirect('/register?err=4');
  } else if(!validateEmail(email)) {
    res.redirect('/register?err=5');
  } else {
  var usr = new User({ username: username, email: email, password: password });
  usr.save(function(err) {
    if(err) {
      console.log(err.key);
      if(err && err.code == 11000) {
        if(JSON.stringify(err).toString().indexOf('username') > -1) {
          res.redirect('/register?err=3');
        } else if(JSON.stringify(err).toString().indexOf('email') > -1) {
          res.redirect('/register?err=2');
        }
      }
    } else {
      console.log('user: ' + usr.username + " saved.");
        res.redirect('/login');
    }

});
  }
});

function validateEmail(email) {
    var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(email);
}


require('./routes')(app, mongoose);

var util = require('util');

app.get('/styles/main.css', function(req, res) {
  var upslashes = '';
  var no_slashes = req.url.split("/").length - 1;
  for(var i = 0; i < no_slashes; i++) {
    upslashes += '../';
  }
  res.setHeader('Content-Type', 'text/css');
  res.render('astro_style', { upslashes: upslashes });
});


app.get('*', function(req, res){
  var upslashes = '';
  var no_slashes = req.url.split("/").length - 1;
  for(var i = 0; i < no_slashes; i++) {
    upslashes += '../';
  }
  res.render('404', { user: req.user, upslashes: upslashes });
});

server.listen(port, function() {
  log.log('Express: '.red + 'Server listening on port :'.green + port.toString().magenta);
});


// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login');
}
function ensureNotAuthenticated(req, res, next) {
  if (!req.isAuthenticated()) { return next(); }
  res.redirect('/');
}
