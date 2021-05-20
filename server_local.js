var https = require('https');
var express = require('express')
var fs = require('fs');
const jwt = require('jsonwebtoken');
var crypto = require('crypto')
const dotenv = require('dotenv');
dotenv.config();

var options = {
  key: fs.readFileSync('Certificate/dev.deliciousbrains.com.key'),
  cert: fs.readFileSync('Certificate/dev.deliciousbrains.com.crt')
};

var privkey = fs.readFileSync('au_private-key.pem');
var publickey = fs.readFileSync('au_public-key.pem');
var header = {
  "alg": "ES256",
  "typ": "JWT"
};
var bodyParser = require('body-parser');
var ipsets = fs.readFileSync('ipdb.txt',  {encoding:'utf8'});
var domains = fs.readFileSync('domains.txt',  {encoding:'utf8'});
var ips =  fs.readFileSync('ips.txt',  {encoding:'utf8'});

var app = express()
app.set('port', 8000)
app.use(bodyParser.json());
//app.use(logger('dev'))
// in latest body-parser use like below.
app.use(bodyParser.urlencoded({ extended: true }));

//console.log(crypto.randomBytes(64).toString('hex'));

//algorithm:'ES256', 
function generateAccessToken(username){
  return jwt.sign(username, privkey, { header:header, expiresIn: '10h' });
  
}
app.post('/', function(req, res){
  var data = req.body;
  if(data.email == "test@test.com" && data.password=="test"){
    const token = generateAccessToken({email:data.email});
	console.log(token);
    res.json({res:token});
  }else{
    res.send({res:"error"});
  }
 
});
app.post('/filterlist', function(req, res){
  var data = req.body;
  var token = data.token;
  if(token){
	jwt.verify(token, publickey, function(err, decoded) {
		if(err){
			res.json({res:'fail'});
		}else{
			res.json({res:'ok', ipsets:ipsets, domains:domains, ips:ips});
		}
	});
  }
});

app.get('/', function(req, res){
  console.log("get received request")
  res.send("recieved your get request!");
});
var httpsServer = https.createServer(options, app);
httpsServer.listen(8000);


