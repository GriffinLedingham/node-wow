var net = require('net')
var Vendor = require('./vendor.js')()
var AuthSocket = require('./classes/authsocket')
var AuthConfig = require('./config/auth_config')

var HOST = AuthConfig.host
var PORT = AuthConfig.port

net.createServer(function(SOCK) {
  var authSocket = new AuthSocket()
  authSocket.init(SOCK, HOST, PORT)
  SOCK.on('data', function(data) {
    authSocket.handle(data)
  })
}).listen(PORT, HOST)
console.log('Server listening on ' + HOST +':'+ PORT)