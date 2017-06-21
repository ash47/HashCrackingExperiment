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
const wordsPerPage = 1000;
var websiteRoot = 'https://speedhasher.com/';

// Max password length
const maxIndexSize = 4;

// Max number of toggles (real is one more than this)
var maxToggleLetters = 9;

// Used for generation of other URLs
const extraChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 !@#$%^&*()-_=+[]{}|\\;:\'"?/,.<>`~';

// List of wordlists we support
const wordLists = {
	rockyou: __dirname + '/wordlists/rockyou.txt'
};

// Read in the common headers
const commonHead = fs.readFileSync(__dirname + '/lib/common_head.htm');
const commonFooter = fs.readFileSync(__dirname + '/lib/footer.htm');

// Remove x-powered-by
app.disable('x-powered-by');

// Add protection headers
app.use(function(req, res, next) {
	// Add headers
	res.setHeader('X-Frame-Options', 'DENY');

	// Logging
	console.log(getDateTime(), req.url, req.connection.remoteAddress, req.headers['user-agent']);

	// Continue
	next();
});

// Static files
app.use(express.static('www'))

// Mapping for sitemaps (xml)
app.get('/sitemaps/:name.xml', function(req, res, next) {
	var sitemapName = req.params.name;

	// Root one
	if(sitemapName == 'root') {

	}

	next();
});

// Mapping for sitemaps (txt)
app.get('/sitemaps/:name.txt', function(req, res, next) {
	var sitemapName = req.params.name;

	if(sitemapName == 'rockyou') {
		var maxWords = 14344391;

		var toOutput = '';

		for(var i=0; i * wordsPerPage<maxWords; ++i) {
			if(i != 0) {
				res.write('\r\n');
			}
			res.write(websiteRoot + 'wordlists/rules/rockyou/' + i + '/passwords.htm');
		}

		res.end();
		return;
	}

	if(sitemapName == 'rockyou_rules') {
		var maxWords = 14344391;

		var toOutput = '';

		for(var i=0; i * wordsPerPage<maxWords; ++i) {
			if(i != 0) {
				res.write('\r\n');
			}
			res.write(websiteRoot + 'wordlists/rules/rockyou/' + i + '/passwords.htm');
		}

		res.end();
		return;
	}

	if(sitemapName == 'level2') {
		res.write(websiteRoot);

		for(var i=0; i<extraChars.length; ++i) {
			var theChar = extraChars[i];

			res.write('\r\n' + websiteRoot + 'rules/' + encodeURIComponent(theChar) + hashExtension);

			for(var j=0; j<extraChars.length; ++j) {
				var theChar2 = extraChars[j];

				res.write('\r\n' + websiteRoot + 'rules/' + encodeURIComponent(theChar) + encodeURIComponent(theChar2) + hashExtension);
			}
		}

		res.end();
		return;
	}

	next();
});

// Mapping for wordlists
app.get('/wordlists/rules/:wordList/:pageNumber/passwords.htm', function(req, res, next) {
	// Handle the request, add rules
	wordlistHandler(req, res, next, true);
});

app.get('/wordlists/:wordList/:pageNumber/passwords.htm', function(req, res, next) {
	var wordList = req.params.wordList;
	var pageNumber = req.params.pageNumber;

	// 301 redirect
	res.redirect(301, '/wordlists/rules/' + encodeURIComponent(wordList) + '/' + encodeURIComponent(pageNumber) + '/passwords.htm');
});

function wordlistHandler(req, res, next, useRules) {
	var wordList = req.params.wordList;
	var pageNumber = 0;

	try {
		pageNumber = parseInt(req.params.pageNumber);

		if(pageNumber < 0) {
			throw new Error('Number less than 0');
		}
	} catch(e) {
		next();
		return;
	}

	var specialText = '';
	if(useRules) {
		specialText = '?rules=true';
	}

	var startEntry = pageNumber * wordsPerPage;

	// Ensure the wordlist actually exists
	if(!wordLists[wordList]) {
		next();
		return;
	}

	var instream = fs.createReadStream(wordLists[wordList]);
	var outstream = new stream();
	var rl = readline.createInterface(instream, outstream);

	var passwordOutput = '';
	var lineNumber = 0;
	rl.on('line', function(line) {
		if(++lineNumber > startEntry) {
			if(lineNumber <= startEntry + wordsPerPage) {
				//toOutput += '<li><a href="/' + encodeURIComponent(line) + '.htm" target="_blank">' + htmlEncode(line) + '</a></li>';
				passwordOutput += calcHashes(line, true, specialText);
			} else {
				// Done
				rl.pause();
				rl.close();
			}
		}
	});

	rl.on('close', function() {
		// Did we actually output enough passwords?
		var nextPageNumber = pageNumber + 1;
		if(lineNumber < startEntry + wordsPerPage) {
			// Next page = 0
			nextPageNumber = 0;

			if(lineNumber < startEntry) {
				startEntry = -1;
				lineNumber = 1;
			}
		}

		var wordlistPath = '/wordlists/';
		if(useRules) {
			wordlistPath = '/wordlists/rules/';
		}

		var passwordsInText = htmlEncode(wordList) + ': ' + htmlEncode(startEntry+1) + ' - ' + htmlEncode(lineNumber - 1);
		var toOutput = '<html><head>' + commonHead + '<title>' + passwordsInText + ' - SpeedHasher.com</title></head><body><div id="content"><h1>Passwords in ' + passwordsInText + '</h1><div class="passwordList">';
		toOutput += passwordOutput;
		toOutput += '</div><a href="' + wordlistPath + htmlEncode(wordList) + '/' + htmlEncode(nextPageNumber) + '/passwords.htm" target="_blank">More Passwords</a>'
		toOutput += commonFooter;
		toOutput += '</div></body></html>'
		res.end(toOutput);
	});
}

// Mapping for rules
app.get('/rules/:toHash.htm', function(req, res, next) {
	var toHash = req.params.toHash;
	
	var allowedChars = /^[A-Za-z0-9 !@#$%^&*()-_=+\[\]{}|\\;:'"?/,.<>`~]+$/g;
	if(!allowedChars.test(toHash)) {
		next();
		return;
	}

	// Should we ignore the max length?
	var ignoreMaxLength = req.query.ignoreMaxLength != null;

	var outputBody = '<html><head>' + commonHead + '<title>Hash of ' + htmlEncode(toHash) + ' - SpeedHasher.com</title></head><body><div id="content">';
	outputBody += calcHashes(toHash, true, '?rules=true');
	
	// Add the backwards link
	if(toHash.length >= 2) {
		var prevPassword = toHash.substr(0, toHash.length - 1);
		outputBody += calcHashes(prevPassword, true, '?rules=true');
	}

	// Add the togglecase rules
	outputBody += rulesToggleCase(toHash, ignoreMaxLength);
	outputBody += rulesLeet(toHash, ignoreMaxLength);
	outputBody += rulesAppendStuff(toHash, ignoreMaxLength);

	outputBody += otherPasswords(toHash, false, '?rules=true');

	outputBody += commonFooter;
	outputBody += '</div></body></html>';

	res.end(outputBody);
});

// Mapping for standard hashing
app.get('/:toHash.htm', function(req, res, next) {
	// Grab what we are going to hash
	var toHash = req.params.toHash;

	// 301 redirect to rules
	res.redirect(301, '/rules/' + encodeURIComponent(toHash) + '.htm');
});

// Landing page
app.get('/', function(req, res, next) {
	res.end(
		'<html><head>' + 
		commonHead + 
		'<title>Hashing Experiment - SpeedHasher.com</title></head>' +
		'<body><div id="content">' + 
		'<h1>Word Lists</h1>' +
		'<a href="/wordlists/rules/rockyou/0/passwords.htm" target="_blank">RockYou + Rules</a>' +
		otherPasswords('', false, '?rules=true') +
		commonFooter +
		'</div></body></html>'
	);
});

// Error handler
app.use(function(err, req, res, next) {
	console.log(err);

	// Send a 404
	res.status(404).end('404');
})

// Create the HTTP server
http.createServer(app).listen(config.port, function () {
	console.log('Server listening on port ' + config.port);
});

// Create the HTTPS server
https.createServer({
	key: fs.readFileSync('creds/creds.key', 'utf8'),
	cert: fs.readFileSync('creds/creds.crt', 'utf8')
}, app).listen(config.sslPort, function () {
	console.log('Server listening on SSL port ' + config.sslPort);
});

// Calculates the hashes of a password
function calcHashes(data, ignoreMaxLength, specialText) {
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

	// Grab the ignore text
	var ignoreText = '';

	if(specialText != null) ignoreText = specialText;
	
	outputResHashes += '<table class="table table-striped hashTable">';

	if(data.length <= maxIndexSize || ignoreMaxLength) {
		if(ignoreText == '?rules=true') {
			outputResHashes += '<tr><th>Input</th><td><a href="/rules/' + encodeURIComponent(data) + hashExtension + '" target="_blank">' + htmlEncode(data) + '</a></td></tr>';
		} else {
			outputResHashes += '<tr><th>Input</th><td><a href="/' + encodeURIComponent(data) + hashExtension + ignoreText + '" target="_blank">' + htmlEncode(data) + '</a></td></tr>';
		}
	} else {
		outputResHashes += '<tr><th>Input</th><td>' + htmlEncode(data) + '</td></tr>';
	}
	
	outputResHashes += '<tr><th>NTLM</th><td>' + lmHash + ':' + ntHash + '</td></tr>';
	outputResHashes += '<tr><th>NTLM (no LM)</th><td>aad3b435b51404eeaad3b435b51404ee:' + ntHash + '</td></tr>';
	outputResHashes += '<tr><th>MD5</th><td>' + md5(data) + '</td></tr>';
	outputResHashes += '<tr><th>SHA-1</th><td>' + sha1(data) + '</td></tr>';
	outputResHashes += '<tr><th>SHA-256</th><td>' + sha256(data) + '</td></tr>';
	outputResHashes += '</table>';

	return outputResHashes;
}

// Generates a list of suggested other passwords
function otherPasswords(data, ignoreMaxLength, specialText) {
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
		outputOtherPasswords += calcHashes(prevPassword, true, specialText);
	}

	/*if(data.length >= maxIndexSize && !ignoreMaxLength) {
		// Make a suggestion to go back to the start
		data = data.substr(0, maxIndexSize-1);
	}*/

	for(var i=0; i<extraChars.length; ++i) {
		var nextPassword = data + extraChars[i];

		//outputOtherPasswords += '<li><a href="/' + encodeURIComponent(nextPassword) + '.htm" target="_blank">' + htmlEncode(nextPassword) + '</a></li>'
		outputOtherPasswords += calcHashes(nextPassword, ignoreMaxLength, specialText);
	}

	//outputOtherPasswords += '</ul>';
	outputOtherPasswords += '</div>';
	outputOtherPasswords += '</div>';

	return outputOtherPasswords;
}

// Runs a toggle case rule on a word:
function rulesToggleCase(data, ignoreMaxLength, upto) {
	if(upto == null) {
		upto = data.length - 1;
		if(upto > maxToggleLetters) {
			var totalLetters = 0;
			for(var i=0; i<data.length; ++i) {
				var theChar = data[i];

				if(theChar.match(/[a-z]/i)) {
					++totalLetters;

					if(totalLetters > maxToggleLetters) {
						upto = i;
						break;
					}
				}
			}
		}
	}

	// If we are on -1, we are done
	if(upto == -1) return '';

	// Grab my char
	var myChar = data[upto];

	// Is this an alpha character?
	if(!myChar.match(/[a-z]/i)) {
		// Nope, recurse
		return rulesToggleCase(data, ignoreMaxLength, upto - 1);
	}

	// Convert our character
	var newChar = myChar.toLowerCase();
	if(newChar == myChar) {
		newChar = myChar.toUpperCase();
	}

	// Grab the new string
	var newString = data.substring(0, upto) + newChar + data.substring(upto + 1);

	// Calculate hashes
	var myOutput = calcHashes(newString, ignoreMaxLength, '?rules=true');

	// Recurse
	myOutput += rulesToggleCase(newString, ignoreMaxLength, upto - 1);
	myOutput += rulesToggleCase(data, ignoreMaxLength, upto - 1);

	return myOutput;
}

function rulesLeet(data, ignoreMaxLength) {
	var myOutput = '';

	myOutput += addIfDifferent(data, data.replace(/i/gi, '1'), ignoreMaxLength);
	myOutput += addIfDifferent(data, data.replace(/l/gi, '1'), ignoreMaxLength);
	myOutput += addIfDifferent(data, data.replace(/z/gi, '2'), ignoreMaxLength);
	myOutput += addIfDifferent(data, data.replace(/e/gi, '3'), ignoreMaxLength);
	myOutput += addIfDifferent(data, data.replace(/a/gi, '4'), ignoreMaxLength);
	myOutput += addIfDifferent(data, data.replace(/s/gi, '5'), ignoreMaxLength);
	myOutput += addIfDifferent(data, data.replace(/b/gi, '6'), ignoreMaxLength);
	myOutput += addIfDifferent(data, data.replace(/t/gi, '7'), ignoreMaxLength);
	myOutput += addIfDifferent(data, data.replace(/b/gi, '8'), ignoreMaxLength);
	myOutput += addIfDifferent(data, data.replace(/g/gi, '9'), ignoreMaxLength);
	myOutput += addIfDifferent(data, data.replace(/o/gi, '0'), ignoreMaxLength);
	myOutput += addIfDifferent(data, data.replace(/a/gi, '@'), ignoreMaxLength);
	myOutput += addIfDifferent(data, data.replace(/s/gi, '$'), ignoreMaxLength);
	myOutput += addIfDifferent(data, data.replace(/h/gi, '#'), ignoreMaxLength);
	
	myOutput += addIfDifferent(
		data, data.replace(/a/gi, '@')
					.replace(/s/gi, '$'),
		ignoreMaxLength
	);
	myOutput += addIfDifferent(
		data, data.replace(/a/gi, '@')
					.replace(/s/gi, '$')
					.replace(/o/gi, '0'),
		ignoreMaxLength
	);
	myOutput += addIfDifferent(
		data, data.replace(/a/gi, '@')
					.replace(/s/gi, '$')
					.replace(/o/gi, '0')
					.replace(/e/gi, '3'),
		ignoreMaxLength
	);

	return myOutput;
}

function rulesAppendStuff(data, ignoreMaxLength) {
	var myOutput = '';

	myOutput += calcHashes(data + '1', ignoreMaxLength, '?rules=true');
	myOutput += calcHashes(data + '123', ignoreMaxLength, '?rules=true');
	myOutput += calcHashes(data + '1234', ignoreMaxLength, '?rules=true');
	myOutput += calcHashes(data + '123#', ignoreMaxLength, '?rules=true');
	myOutput += calcHashes(data + '123#$', ignoreMaxLength, '?rules=true');
	myOutput += calcHashes(data + '123#$%', ignoreMaxLength, '?rules=true');
	myOutput += calcHashes(data + '1234$', ignoreMaxLength, '?rules=true');
	myOutput += calcHashes(data + '1234$%', ignoreMaxLength, '?rules=true');
	myOutput += calcHashes(data + '!23', ignoreMaxLength, '?rules=true');
	myOutput += calcHashes(data + '!@#', ignoreMaxLength, '?rules=true');
	myOutput += calcHashes(data + '123!@#', ignoreMaxLength, '?rules=true');
	myOutput += calcHashes(data + '123!@#$', ignoreMaxLength, '?rules=true');

	return myOutput;
}

// Returns hashes of string2 if it's different to string1
function addIfDifferent(str1, str2, ignoreMaxLength) {
	if(str1 == str2) return '';
	return calcHashes(str2, ignoreMaxLength, '?rules=true');
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
