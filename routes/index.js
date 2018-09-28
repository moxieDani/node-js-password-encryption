var crypto = require('crypto');
var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', {error: null});
});

router.post('/check', function(req, res, next) {
  var salt = "";
  crypto.randomBytes(64, (err, buf) => {
    salt = buf.toString('base64');
    crypto.pbkdf2(req.body.password, salt, 100000, 64, 'sha512', (err, key) => {
      res.render('check', {error:null, password:key.toString('base64'), salt:salt});
    });
  });
});

router.post('/result', function(req, res, next) {
  var salt = req.body.salt;
  var inputPassword = req.body.inputPassword;
  var checkPassword = req.body.checkPassword;
  crypto.pbkdf2(checkPassword, salt, 100000, 64, 'sha512', (err, key) => {
    if (key.toString('base64') === inputPassword) {
      res.render('result', {error:null});
    } else {
      res.render('check', {error:'Invalid Password', password:inputPassword, salt:salt});
    }
  });
});

module.exports = router;
