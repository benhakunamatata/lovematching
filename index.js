var express = require('express');
var app = express();
var fs = require("fs");
var multer  = require('multer');
var path = require('path');
var mysql = require('mysql');
var bodyParser = require('body-parser');
var session = require('express-session');
var crypto = require('crypto');
var md5 = require('md5');

// var con = mysql.createConnection({
//   host: "us-cdbr-iron-east-05.cleardb.net",
//   user: "b7a1678db913ee",
//   password: "23a7a6b7",
//   database: "heroku_300a7e4fe3385cb"
// });

var pool = mysql.createPool({
    connectionLimit: 10, //important
    host: "xxx",
    user: "xxx",
    password: "xxx",
    database: "xxx",
    debug: false
});

function hitQuery(user_query, res, callback) {
    pool.getConnection(function(err, connection) {
        if (err) {
            connection.release();
            res.json({ "code": 100, "status": "Error in connection database" });
            return;
        }
        connection.query(user_query, function(err, rows, fields) {
            if (err) {
              callback(err, null);
            } else {
              if (rows.length == 0) {
                  callback(null, null);
              } else {
                  callback(null, rows);
              }
            }
        });
    });
}

var MAGIC_NUMBERS = {
    jpg: 'ffd8ffe0',
    jpg1: 'ffd8ffe1',
    png: '89504e47',
    gif: '47494638'
}

function checkMagicNumbers(magic) {
    if (magic == MAGIC_NUMBERS.jpg || magic == MAGIC_NUMBERS.jpg1 || magic == MAGIC_NUMBERS.png || magic == MAGIC_NUMBERS.gif) return true
}

function mysql_real_escape_string (str) {
    return str.replace(/[\0\x08\x09\x1a\n\r"'\\\%]/g, function (char) {
        switch (char) {
            case "\0":
                return "\\0";
            case "\x08":
                return "\\b";
            case "\x09":
                return "\\t";
            case "\x1a":
                return "\\z";
            case "\n":
                return "\\n";
            case "\r":
                return "\\r";
            case "\"":
            case "'":
            case "\\":
            case "%":
                return "\\"+char; // prepends a backslash to backslash, percent,
                                  // and double/single quotes
        }
    });
}

function getFormVal(req, key) {
  var formVal = (req.body[key] || '').trim()
  return mysql_real_escape_string(formVal)
}

/**
 * generates random string of characters i.e salt
 * @function
 * @param {number} length - Length of the random string.
 */
var genRandomString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
            .toString('hex') /** convert to hexadecimal format */
            .slice(0,length);   /** return required number of characters */
};

/**
 * hash password with sha512.
 * @function
 * @param {string} password - List of required fields.
 * @param {string} salt - Data to be validated.
 */
var sha512 = function(password, salt){
    var hash = crypto.createHmac('sha256', salt); /** Hashing algorithm sha512 */
    hash.update(password);
    var value = hash.digest('hex');
    return {
        salt:salt,
        passwordHash:value
    };
};


app.set('port', (process.env.PORT || 5000));

app.use(express.static(__dirname + '/public'));


app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});

app.use(session({
    secret: "keyboardcat",
    name: "mycookie",
    user_id: '',
    user: {},
    resave: true,
    saveUninitialized: true,
    cookie: {
        secure: false,
        maxAge: 6000000
    }
}));


function checkAuth(req, res, next) {
  if (!req.session.userid) {
    //res.send('You are not authorized to view this page');
    res.redirect('/login');
  } else {
    next();
  }
}

// app.use(multer({ dest: __dirname + '/public/upload/'}));

// views is directory for all template files
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');


app.get('/', function(request, response) {
  var dbUrl = process.env.DATABASE_URL;
  response.render('pages/index', {dburl: dbUrl});
});


app.get('/welcome', checkAuth, function(request, response) {
  var user = {};
  if(request.session.user) {
    user = request.session.user;
  }
  response.render('pages/welcome', {user: user});
});

app.get('/admin/welcome', function(request, response) {
  response.render('pages/adminwelcome')
});

app.get('/matchresults', function(request, response) {
  response.render('pages/matchresults')
});

app.get('/myprofile', function(req, res) {
  res.render('pages/myprofile', {user: req.session.user})
});

app.get('/register', function(request, response) {
  response.render('pages/register')
});

app.post('/register', function(req, res) {
  var sql = getRegisterSql(req);
  hitQuery(sql, res, function (err, result) {
    if (err) {
      var json = JSON.stringify({message: "User already registered!"});
      res.writeHead(200, {"Content-Type": "application/json"});
      res.end(json);
    } else {
      res.writeHead(200, {"Content-Type": "application/json"});
      var json = JSON.stringify({message: "Successfully Registered!"});
      res.end(json);
    }
  });
});

app.get('/login', function(request, response) {
  response.render('pages/login');
});

app.get('/admin/login', function(request, response) {
  response.render('pages/admin/login');
});

app.get('/logout', function (req, res) {
  delete req.session.user_id;
  res.redirect('/login');
});

app.post('/login', function(req, res) {
  var sql = getLoginSql(req);
  hitQuery(sql, res, function (err, result) {
    if (err || !result) {
      res.writeHead(200, {"Content-Type": "application/json"});
      var json = JSON.stringify({message: "Login Credential is not right!"});
      res.end(json);
    } else {
      req.session.user_id = '1';
      if(!req.session.user) {
        req.session.user = {};
      }
      req.session.user = result[0];
      req.session.user.email = getFormVal(req, 'email');
      req.session.userid = req.session.user.userid;
      if(!req.session.user.image) {
        req.session.user.image = 'default_' + req.session.user.gender + ".jpg";
      }

      req.session.save(function (err) {
        var redirectUrl = "/welcome";
        var json = JSON.stringify({message: "success", redirectUrl: redirectUrl});
        res.writeHead(200, {"Content-Type": "application/json"});
        res.end(json);
      });
    }
  });

});


app.post('/admin/login', function(req, res) {
  var sql = getLoginSql(req);
  hitQuery(sql, res, function (err, result) {
    if (err || !result) {
      var json = JSON.stringify({message: "Login Credential is not right!"});
      res.writeHead(200, {"Content-Type": "application/json"});
      res.end(json);
    } else {
      req.session.user_id = '1';
      if(!req.session.user) {
        req.session.user = {};
      }
      req.session.user = result[0];
      req.session.user.email = getFormVal(req, 'email');
      req.session.userid = req.session.user.userid;
      if(!req.session.user.image) {
        req.session.user.image = 'default_' + req.session.user.gender + ".jpg";
      }
      req.session.save(function (err) {
        var redirectUrl = "/admin/welcome";
        var json = JSON.stringify({message: "success", redirectUrl: redirectUrl});
        res.writeHead(200, {"Content-Type": "application/json"});
        res.end(json);
      });
    }
  });

});

app.get('/admin/viewinfo', function(req, res) {
  var results = [];
  var sql = "SELECT userid,firstname,lastname,email,phonenumber,uid FROM users";
  hitQuery(sql, res, function (err, result) {
    if (err) {
      throw err;
    } else {
      res.render('pages/admin/viewinfo', {results: result});
    }
    // console.log("Number of records inserted: " + result.affectedRows);
  });
});

app.get('/admin/manageinfo', function(request, response) {
  if(request.query.uid) {
    var sql = "SELECT userid,firstname,lastname,email,phonenumber,matchids,profile,wechatid,activity  FROM users where uid = " + request.query.uid;
    hitQuery(sql, response, function (err, result) {
      if (err) {
        console.log(err);
        response.render('pages/manageinfo');
        // throw err;
      } else {
        response.render('pages/manageinfo2', {user: result[0]});
      }
      // console.log("Number of records inserted: " + result.affectedRows);
    });
  } else {
    response.render('pages/manageinfo');
  }
});

function getLoginSql(req) {
  var sql = "SELECT uid, userid, email, firstname, gender,image,matchids from users where email = '" + getFormVal(req, 'email')+  "' and password='"+ getFormVal(req, 'password')+"'"
  return sql;
}

function getAdminLoginSql(req) {
  var sql = "SELECT uid, userid, email, firstname, gender,image,matchids from users where status = -1 AND email = '" + getFormVal(req, 'email')+  "' and password='"+ getFormVal(req, 'password')+"'"
  return sql;
}

function getRegisterSql(req) {
  var sql = "INSERT INTO users (`userid`, `email`, `firstname`, `gender`, `password`) VALUES ('";
  sql = sql + getFormVal(req, 'userid') + "','" + getFormVal(req, 'email')+"','" + getFormVal(req, 'firstname') +"','" + getFormVal(req, 'gender') +"','" + getFormVal(req, 'password') + "')";
  return sql;
}

function getSql(req) {
  var sql = "INSERT INTO users (`userid`, `email`, `firstname`, `lastname`, `profile`, `wechatid`, `phonenumber`, `gender`, `activity`) VALUES ('";
  sql = sql + getFormVal(req, 'userid') + "','" + getFormVal(req, 'email')+"','" + getFormVal(req, 'firstname') +"','" + getFormVal(req, 'lastname') +"','"
  sql = sql + getFormVal(req, 'profile') + "','" + getFormVal(req, 'wechatid') +"','"+ getFormVal(req, 'phonenumber')+ "','"+ getFormVal(req, 'gender') + "','"+ getFormVal(req, 'activity');;
  sql = sql + "') ON DUPLICATE KEY UPDATE  firstname = '" + getFormVal(req, 'firstname')
  sql = sql + "', gender = '" + getFormVal(req, 'gender')
  sql = sql + "', lastname = '" + getFormVal(req, 'lastname')
  sql = sql + "', profile = '" + getFormVal(req, 'profile')
  sql = sql + "', wechatid = '" + getFormVal(req, 'wechatid')
  sql = sql + "', phonenumber = '" + getFormVal(req, 'phonenumber')
  sql = sql + "', activity = '" + getFormVal(req, 'activity')
  sql = sql + "', userid= '" + getFormVal(req, 'userid') + "'";
  return sql;
}


app.post('/admin/manageinfo', function(req, res) {
  if(getFormVal(req, 'firstname')) {
    res.write('You sent the First Name "' + getFormVal(req, 'firstname') +'".\n');
  }
  if(getFormVal(req, 'lastname')) {
    res.write('You sent the Last Name "' + getFormVal(req, 'lastname') +'".\n');
  }
  if(getFormVal(req, 'email')) {
    res.write('You sent the Email "' + getFormVal(req, 'email') +'".\n');
  }
  if(getFormVal(req, 'profile')) {
    res.write('You sent the Profile "' + getFormVal(req, 'profile') +'".\n');
  }
  if(getFormVal(req, 'wechatid')) {
    res.write('You sent the WebChat Id "' + getFormVal(req, 'wechatid') +'".\n');
  }
  if(getFormVal(req, 'phonenumber')) {
    res.write('You sent the Phone Number "' + getFormVal(req, 'phonenumber') +'".\n');
  }
  if(getFormVal(req, 'gender')) {
    res.write('You sent the Gender "' + getFormVal(req, 'gender') +'".\n');
  }
  res.end();

  var sql = getSql(req);
  hitQuery(sql, res, function (err, result) {
    if (err) throw err;
    // console.log(result);
    // console.log("Number of records inserted: " + result.affectedRows);
  });

});

app.get('/selectmatch', checkAuth, function(req, res) {
  var curGender = req.session.user.gender;
  var oppositeGender = 'female';
  if(curGender == 'female') {
    oppositeGender = 'male';
  }
  var defaultImage = 'default_' + oppositeGender + '.jpg';
  var results = [];
  var sql = "SELECT userid,firstname,image FROM users where gender != '"+curGender+"' ";
  hitQuery(sql, res, function (err, result) {
    if (err) {
      throw err;
    } else {
      var choices = [];
      if(req.session.user.matchids) {
        choices = req.session.user.matchids.split(',');
      }
      for(var i=0; i<result.length; i++) {
        if(!result[i].image) {
          result[i].image = defaultImage;
        }
        if(choices.indexOf(result[i].userid.toString() ) == -1) {
          result[i].checked = "";
        } else {
          result[i].checked = "checked";
        }
      }
      res.render('pages/selectmatch', {results: result});
    }
  });
});

app.post('/selectmatch', function(req, res) {
  var curUid = req.session.user.uid;
  req.session.user.matchids = req.body.choices.join();
  var sql = "UPDATE users SET matchids = '" + req.body.choices.join() +  "' WHERE uid = " + curUid;
  hitQuery(sql, res, function (err, result) {
    if (err) {
      var json = JSON.stringify({status: "error", message: "error happened during saving", error: err});
      res.writeHead(200, {"Content-Type": "application/json"});
      res.end(json);
    } else {
      res.writeHead(200, {"Content-Type": "application/json"});
      var json = JSON.stringify({status: "success", message: "Successfully saved matching results!"});
      res.end(json);
    }
  });
});

app.get('/mypicture', function(req, res) {
  res.render('pages/mypicture', {imageUrl: req.session.user.image});
});

app.post('/mypicture', function(req, res) {
    var upload = multer({
        storage: multer.memoryStorage()
    }).single('userFile');
    upload(req, res, function(err) {
        var buffer = req.file.buffer;
        var magic = buffer.toString('hex', 0, 4);
        // var filename = req.file.fieldname + '-' + Date.now() + path.extname(req.file.originalname);
        var filename = md5(req.session.user.email) + '.png';
        req.session.user.image = filename;
        if (checkMagicNumbers(magic)) {
            fs.writeFile('./public/upload/' + filename, buffer, 'binary', function(err) {
                if (err) throw err
                // res.end('File is uploaded')
                // res.redirect(307, "/mypicture");
                // res.send({err: 0, redirectUrl: "/mypicture"});
                var sql = "UPDATE users SET image = '" + filename + "' WHERE uid = " + req.session.user.uid;
                hitQuery(sql, res, function (err, result) {
                  if (err) {
                    throw err;
                  } else {
                    res.render('pages/mypicture', {imageUrl: filename});
                  }
                });
            });
        } else {
            res.end('File is no valid');
        }
    });
});

app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});
