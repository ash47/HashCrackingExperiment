// Crypto Imports
const lmhash = require('./lib/smbhash.js').lmhash;
const nthash = require('./lib/smbhash.js').nthash;
const crypto = require('crypto');

// IO Imports
const fs = require('fs');
const readline = require('readline');
const stream = require('stream');

// Webserver Imports
const express = require('express');
const app = express();
const http = require('http');
const https = require('https');

const config = require('./config.json');

// Config
const hashExtension = '.htm';
const wordsPerPage = 100;

// Max password length
const maxIndexSize = 4;

// Used for generation of other URLs
const extraChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 !@#$%^&*()-_=+[]{}|\\;:\'"?/,.<>`~';

// List of wordlists we support
const wordLists = {
	rockyou: __dirname + '/wordlists/rockyou.txt'
};

// Read in the common headers
const commonHead = fs.readFileSync(__dirname + '/lib/common_head.htm');
const commonFooter = fs.readFileSync(__dirname + '/lib/footer.htm');

// Static files
app.use(express.static('www'))

// Mapping for wordlists
app.get('/wordlists/:wordList/:startEntry/passwords.htm', function(req, res, next) {
	var wordList = req.params.wordList;
	var startEntry = req.params.startEntry;

	// Ensure the wordlist actually exists
	if(!wordLists[wordList]) {
		next();
		return;
	}

	try {
		// Try to parse it
		startEntry = parseInt(startEntry);

		if(startEntry < 0) {
			throw new Error('Number less than 0');
		}
	} catch(e) {
		next();
		return;
	}

	var nextPasswordsPage = (startEntry + wordsPerPage);

	var instream = fs.createReadStream(wordLists[wordList]);
	var outstream = new stream();
	var rl = readline.createInterface(instream, outstream);

	var passwordsInText = htmlEncode(wordList) + ': ' + htmlEncode(startEntry) + ' - ' + htmlEncode(nextPasswordsPage - 1);
	var toOutput = '<html><head>' + commonHead + '<title>' + passwordsInText + ' - SpeedHasher.com</title></head><body><div id="content"><h1>Passwords in ' + passwordsInText + '</h1><div class="passwordList">';
	var lineNumber = 0;
	rl.on('line', function(line) {
		if(++lineNumber > startEntry) {
			if(lineNumber <= startEntry + wordsPerPage) {
				//toOutput += '<li><a href="/' + encodeURIComponent(line) + '.htm" target="_blank">' + htmlEncode(line) + '</a></li>';
				toOutput += calcHashes(line);
			} else {
				// Done
				rl.close();
			}
		}
	});

	rl.on('close', function() {
		// Did we actually output enough passwords?
		if(lineNumber < startEntry + wordsPerPage) {
			// Next page = 0
			nextPasswordsPage = 0;
		}

		toOutput += '</div><a href="/wordlists/' + htmlEncode(wordList) + '/' + htmlEncode(nextPasswordsPage) + '/passwords.htm" target="_blank">More Passwords</a>'
		toOutput += commonFooter;
		toOutput += '</div></body></html>'
		res.end(toOutput);
	});
});

// Mapping for hashes
app.use(function(req, res, next) {
	var url = req.url;

	console.log(getDateTime(), url, req.connection.remoteAddress, req.headers['user-agent']);

	if(url == '/') {
		// Root page
		res.end('<html><head>' + commonHead + '<title>Hashing Experiment - SpeedHasher.com</title></head><body><div id="content"><h1>Word Lists</h1><a href="/wordlists/rockyou/0/passwords.htm">RockYou</a>' + otherPasswords('') + commonFooter + '</div></body></html>');
		return;
	}

	if(url.lastIndexOf(hashExtension) == url.length - hashExtension.length) {
		var toMatch;

		// Ensure it is valid
		try {
			toMatch = '' + decodeURIComponent(url.substr(1, url.length - hashExtension.length - 1));
		} catch(e) {
			next();
			return;
		}

		var allowedChars = /^[A-Za-z0-9 !@#$%^&*()-_=+\[\]{}|\\;:'"?/,.<>`~]+$/g;
		if(!allowedChars.test(toMatch)) {
			console.log('test failed: ' + toMatch);
			next();
			return;
		}

		res.status(200);

		var outputBody = '<html><head>' + commonHead + '<title>Hash of ' + htmlEncode(toMatch) + ' - SpeedHasher.com</title></head><body><div id="content">';
		outputBody += calcHashes(toMatch);
		outputBody += otherPasswords(toMatch);
		outputBody += commonFooter;
		outputBody += '</div></body></html>';

		res.end(outputBody);
		return;
	}

	next();
});

http.createServer(app).listen(config.port, function () {
	console.log('Server listening on port ' + config.port);
});

https.createServer({
	key: fs.readFileSync('creds/creds.key', 'utf8'),
	cert: fs.readFileSync('creds/creds.crt', 'utf8')
}, app).listen(config.sslPort, function () {
	console.log('Server listening on SSL port ' + config.sslPort);
});

// Calculates the hashes of a password
function calcHashes(data) {
	var outputResHashes = '';

	var lmHash = '';
	var ntHash = '';

	try {
		lmHash = lmhash(data).toLowerCase();
	} catch(e) {
		// Do nothing
	}

	try {
		ntHash = nthash(data).toLowerCase();
	} catch(e) {
		// Do nothing
	}
	
	outputResHashes += '<table class="table table-striped hashTable">';
	outputResHashes += '<tr><th>Input</th><td><a href="/' + encodeURIComponent(data) + '.htm" target="_blank">' + htmlEncode(data) + '</a></td></tr>';
	outputResHashes += '<tr><th>NTLM</th><td>' + lmHash + ':' + ntHash + '</td></tr>';
	outputResHashes += '<tr><th>NTLM (no LM)</th><td>aad3b435b51404eeaad3b435b51404ee:' + ntHash + '</td></tr>';
	outputResHashes += '<tr><th>MD5</th><td>' + md5(data) + '</td></tr>';
	outputResHashes += '<tr><th>SHA-1</th><td>' + sha1(data) + '</td></tr>';
	outputResHashes += '<tr><th>SHA-256</th><td>' + sha256(data) + '</td></tr>';
	outputResHashes += '</table>';

	return outputResHashes;
}

// Generates a list of suggested other passwords
function otherPasswords(data) {
	if(data.length >= maxIndexSize) {
		// Make a suggestion to go back to the start
		data = '';
	}

	var outputOtherPasswords = '';
	outputOtherPasswords += '<div>';
	outputOtherPasswords += '<h1>Hash a Password</h1>';
	outputOtherPasswords += '<div id="hashPassword"></div>';
	outputOtherPasswords += '<h1>Other Passwords</h1>';

	outputOtherPasswords += '<div class="otherPasswords">';
	//outputOtherPasswords += '<div class="otherPasswords"><ul>';

	if(data.length >= 2) {
		var prevPassword = data.substr(0, data.length - 1);
		//outputOtherPasswords += '<li><a href="/' + encodeURIComponent(prevPassword) + '.htm" target="_blank">' + htmlEncode(prevPassword) + '</a></li>'
		outputOtherPasswords += calcHashes(prevPassword);
	}

	for(var i=0; i<extraChars.length; ++i) {
		var nextPassword = data + extraChars[i];

		//outputOtherPasswords += '<li><a href="/' + encodeURIComponent(nextPassword) + '.htm" target="_blank">' + htmlEncode(nextPassword) + '</a></li>'
		outputOtherPasswords += calcHashes(nextPassword);
	}

	//outputOtherPasswords += '</ul>';
	outputOtherPasswords += '</div>';
	outputOtherPasswords += '</div>';

	return outputOtherPasswords;
}

function getDateTime() {
    var date = new Date();

    var hour = date.getHours();
    hour = (hour < 10 ? '0' : '') + hour;

    var min  = date.getMinutes();
    min = (min < 10 ? '0' : '') + min;

    var sec  = date.getSeconds();
    sec = (sec < 10 ? '0' : '') + sec;

    var year = date.getFullYear();

    var month = date.getMonth() + 1;
    month = (month < 10 ? '0' : '') + month;

    var day  = date.getDate();
    day = (day < 10 ? '0' : '') + day;

    return year + '/' + month + '/' + day + ' ' + hour + ':' + min + ':' + sec;
}

// HTML Encodes a string
function htmlEncode(data) {
	data = '' + data;

	return data
		.replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/\//g, '&#x2F;')
        .replace(/ /g, '&nbsp;');
}

// Computes a sha256 based on the given data
function sha256(data) {
	return crypto.createHash('sha256').update(data).digest('hex');
}

// Creates a MD5 based on the given data
function md5(data) {
	return crypto.createHash('md5').update(data).digest('hex');
}

// Creates a SHA1 based on the given data
function sha1(data) {
	return crypto.createHash('sha1').update(data).digest('hex');
}
