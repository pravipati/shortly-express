var express = require('express');
var util = require('./lib/utility');
var partials = require('express-partials');
var bodyParser = require('body-parser');
var urlParse = require('url');
var Promise = require('bluebird');
var bcrypt = Promise.promisifyAll(require('bcrypt-nodejs'));
var cookieParser = require('cookie-parser');
var cookie = require('cookie');

var db = require('./app/config');
var Users = require('./app/collections/users');
var User = require('./app/models/user');
var Links = require('./app/collections/links');
var Link = require('./app/models/link');
var Click = require('./app/models/click');

var app = express();

app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');
app.use(partials());
// Parse JSON (uniform resource locators)
app.use(bodyParser.json());
// Parse forms (signup/login)
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(__dirname + '/public'));
app.use(cookieParser());

app.get('/',
function(req, res) {
  sessionCheck(req,res, function(){
    res.render('index');
  });
});

app.get('/create',
function(req, res, checked) {
  sessionCheck(req,res, function(){
    res.render('index');
  });
});

app.get('/login',
  function(req,res){
    res.render('login');
  });

app.get('/signup',
function(req, res) {
  res.render('signup');
});

app.get('/links',
function(req, res) {
sessionCheck(req,res, function(){
    Links.reset().fetch().then(function(links) {
      res.send(200, links.models);
    });
  });
});

app.post('/links',
function(req, res) {
  var uri = req.body.url;

  if (!util.isValidUrl(uri)) {
    console.log('Not a valid url: ', uri);
    return res.send(404);
  }

  new Link({ url: uri }).fetch().then(function(found) {
    if (found) {
      res.send(200, found.attributes);
    } else {
      util.getUrlTitle(uri, function(err, title) {
        if (err) {
          console.log('Error reading URL heading: ', err);
          return res.send(404);
        }

        var link = new Link({
          url: uri,
          title: title,
          base_url: req.headers.origin
        });

        link.save().then(function(newLink) {
          Links.add(newLink);
          res.send(200, newLink);
        });
      });
    }
  });
});

/************************************************************/
// Write your authentication routes here
/************************************************************/

app.post('/signup',
  function(req, res) {
  var username = req.body.username;
  var password = req.body.password;
  // var salt = genHash(password);
  // console.log(salt);
  bcrypt.genSaltAsync(10).then(function(salt){
    bcrypt.hashAsync(password,salt,null).then(function(hash){
      db.knex('users')
        .insert({username: username, password: hash})
        .then(function(id){
          console.log('User created with ID #' + id);
          setToken(id,res);
      });
    });
  });
});

var setToken = function(userID,res){
  bcrypt.hashAsync(Date.now(),null,null).then(function(dateHash){
    db.knex('tokens')
      .insert({token: dateHash, userid: userID, created_at: Date.now(), updated_at: Date.now()}).then(function(id){
        res.cookie('token', dateHash);
        res.redirect('/');
      });
  });
};




app.post('/login',
  function(req,res){
    var username = req.body.username;
    var password = req.body.password;
    db.knex('users')
      .where('username',username)
      .select('password','id').then(function(result){
        if (result.length === 0) res.redirect('/signup');
        bcrypt.compareAsync(password,result[0].password)
        .then(function(match){
          if (match){
            setToken(result[0].id,res);
          }
          else res.redirect('/login');
        });
      });
  });

app.post('/logout',
  function(req,res){
  var token = req.cookies.token;
  db.knex('tokens')
    .where('token',token)
    .del()
    .then(function(deleted){
      console.log('Removed ' + deleted + ' tokens from authorized users.');
      res.redirect('/signup');
    });
});

var sessionCheck = function(req,res, callback){
var token = req.cookies.token;
console.log('cookies from session check ' + req.cookies);
if (!token) res.redirect('/signup');
db.knex('tokens')
  .where('token',token)
  .then(function(result){
    if(result.length === 0 || result[0].created_at + 86400000 < Date.now()){
      res.redirect('/login');
    }
    else callback();
  });
};
//get token from cookie
//check token against database
//if token is in database & not expired
//proceed
//else redirect to login page



/************************************************************/
// Handle the wildcard route last - if all other routes fail
// assume the route is a short code and try and handle it here.
// If the short-code doesn't exist, send the user to '/'
/************************************************************/

app.get('/*', function(req, res) {
  new Link({ code: req.params[0] }).fetch().then(function(link) {
    if (!link) {
      res.redirect('/');
    } else {
      var click = new Click({
        link_id: link.get('id')
      });

      click.save().then(function() {
        db.knex('urls')
          .where('code', '=', link.get('code'))
          .update({
            visits: link.get('visits') + 1,
          }).then(function() {
            return res.redirect(link.get('url'));
          });
      });
    }
  });
});

console.log('Shortly is listening on 4568');
app.listen(4568);
