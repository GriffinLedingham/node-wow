var crypto = require('crypto');
var AuthConfig = require('../config/auth_config')

function AuthSocket() {};

AuthSocket.prototype.init = function(sock, host, port) {
  this.sock = sock
  this.srp  = new SRP();
  this.N    = new BigInteger(AuthConfig.N, 16);
  this.g    = new BigInteger(AuthConfig.g);
};

AuthSocket.prototype.handle = function(data) {
  var jsonData = data.toJSON().data;
  var typeOpCode = jsonData[0];
  switch(typeOpCode){
    case 0:
      this.logonChallenge(data);
      break;
    default:
      break;
  }
};

AuthSocket.prototype.logonChallenge = function(data) {
  var str = ''
  var response = []
  var username = ''

  for(var i = 34;i<34+data.toJSON().data[33];i++){
    username +=  String.fromCharCode(data.toJSON().data[i])
  }

  this.I = username.toUpperCase()

  //This should do a DB look up for provided username to see if exists
  if(username != 'A'){
    var c = 0
    var payload = new Uint8Array(3)
    payload[c] = 0;c++
    payload[c] = 0;c++
    payload[c] = 0x04;c++
    this.sock.write(new Buffer(payload))
  }
  else{
      this.p = "a"
      this.s = this.srp.computeRandom()
      this.x = new BigInteger(SHA1(this.s + SHA1(this.I.toUpperCase() + ":" + this.p.toUpperCase())))
      this.v = this.g.modPow(this.x, this.N) // g^x

      this.k = new BigInteger('3')
      this.b = this.srp.computeRandom()
      this.B = this.k.multiply(this.v).add(this.g.modPow(this.b, this.N)).mod(this.N) // k*v + g^b % N

      rndBuf = crypto.randomBytes(16)
      this.unk = new BigInteger(rndBuf, 256)
      this.unk = this.unk.abs()

      function memcopy(target, index, source){
        for(var i = 0;i<source.length;i++){
          target[index+i] = source[i]
        }
        return target
      }

      var c = 0
      var payload = new Uint8Array(200)
      payload[c] = 0;c++
      payload[c] = 0;c++
      payload[c] = 0x00;c++
      payload = memcopy(payload, c, this.B.toByteArray());c+=32
      payload[c] = AuthConfig.g_len;c++
      payload[c] = this.g.toByteArray();c++
      payload[c] = AuthConfig.N_len;c++
      payload = memcopy(payload, c, this.N.toByteArray());c+=32
      payload = memcopy(payload, c, this.s.toByteArray());c+=this.s.toByteArray().length
      payload = memcopy(payload, c, this.unk.toByteArray());c+=16
      payload[c] = 0;c++

      this.sock.write(new Buffer(payload))
  }
}

module.exports = AuthSocket