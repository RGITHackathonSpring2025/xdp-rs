const https = require('https');
const fs = require('fs');

// Read the self-signed certificate and key files
const options = {
  key: fs.readFileSync('./key.pem'),
  cert: fs.readFileSync('./cert.pem')
};

https.createServer(options, (req, res) => {
  res.writeHead(200);
  res.end('Hello World!\n');
}).listen(8443, () => {
  console.log('HTTPS server running at https://localhost:8443/');
});
