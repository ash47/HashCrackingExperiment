// Crypto Imports
const lmhash = require('./lib/smbhash.js').lmhash;
const nthash = require('./lib/smbhash.js').nthash;
const crypto = require('crypto');

// IO Imports
const fs = require('fs');
const readline = require('readline');
const stream = require('stream');
const winston = require('winston');

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
var wordLists = {};
var siteMaps = {};

// Async reload of wordlists
var reloadInProgress = false;
var reloadFinishList = [];
function reloadWordlists(callback) {
	if(callback != null) reloadFinishList.push(callback);
	if(reloadInProgress) return;
	reloadInProgress = true;

	// Log what is happening
	winston.info('Reloading all wordlists...');

	// Read in the config file
	fs.readFile('./wordlists.json', function(err, data) {
		if(err) {
			winston.info('Failed to load wordlists!');
		}

		var wordListsTemp = {};
		try {
			wordListsTemp = JSON.parse(data);
		} catch(e) {
			// Do nothing
		}

		var siteMapsTemp = {};

		var totalLeft = 0;
		var checkDone = function() {
			if(--totalLeft <= 0) {
				// Store the changes
				wordLists = wordListsTemp;
				siteMaps = siteMapsTemp;

				// Done reloading
				reloadInProgress = false;
				var allCallbacks = reloadFinishList;
				reloadFinishList = [];

				// Run all callbacks
				for(var i=0; i<allCallbacks.length; ++i) {
					allCallbacks[i]();
				}
			}
		}

		// Function to count how many lines in a file
		var readLines = function(wordListName) {
			var myInfo = wordListsTemp[wordListName];

			var instream = fs.createReadStream(myInfo.file);
			var outstream = new stream();
			var rl = readline.createInterface(instream, outstream);

			var totalLines = 0;
			rl.on('line', function(line) {
				++totalLines;
			});

			rl.on('close', function() {
				// Store the number of lines
				siteMapsTemp[myInfo.sitemapName] = {
					lines: totalLines,
					path: wordListName
				};

				checkDone();
			});
		}

		// Increase the total number of reload
		for(var wordListName in wordListsTemp) {
			++totalLeft;
		}

		if(totalLeft == 0) {
			totalLeft = 1;
			checkDone();
		} else {
			// Reload them all
			for(var wordListName in wordListsTemp) {
				readLines(wordListName);
			}	
		}
	});
}

// Read in the common headers
const commonHead = fs.readFileSync(__dirname + '/lib/common_head.htm');
const commonFooter = fs.readFileSync(__dirname + '/lib/footer.htm');

// Enable compression
app.use(require('compression')());

// Remove x-powered-by
app.disable('x-powered-by');

// Add protection headers
app.use(function(req, res, next) {
	// Add headers
	res.setHeader('X-Frame-Options', 'DENY');

	// Logging
	winston.info(getDateTime(), req.url, req.connection.remoteAddress, req.headers['user-agent']);

	// Continue
	next();
});

// Mapping for rules
app.get('/rules/:toHash.htm', function(req, res, next) {
	var toHash = req.params.toHash;

	// Should we ignore the max length?
	var ignoreMaxLength = req.query.ignoreMaxLength != null;

	var outputBody = '<html><head>' + commonHead + '<title>Hash of ' + htmlEncode(toHash) + ' - SpeedHasher.com</title></head><body><div id="content">';
	outputBody += calcHashes(toHash, {
		alwaysHyperlink: true
	});

	outputBody += hashPasswordSection();
	
	// Add the backwards link
	if(toHash.length >= 2) {
		outputBody += '<h1>Previous Password</h1>';

		var prevPassword = toHash.substr(0, toHash.length - 1);
		outputBody += calcHashes(prevPassword, {
			alwaysHyperlink: true
		});
	}

	// Add the togglecase rules
	outputBody += '<h1>Password Permutations</h1>';
	outputBody += rulesToggleCase(toHash, ignoreMaxLength);
	outputBody += rulesLeet(toHash, ignoreMaxLength);
	outputBody += rulesAppendStuff(toHash, ignoreMaxLength);

	outputBody += otherPasswords(toHash);

	outputBody += commonFooter;
	outputBody += '</div></body></html>';

	res.send(outputBody);
});

// Mapping for wordlists
app.get('/wordlists/rules/:wordList/:pageNumber/passwords.htm', function(req, res, next) {
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

	var startEntry = pageNumber * wordsPerPage;

	// Ensure the wordlist actually exists
	if(!wordLists[wordList]) {
		next();
		return;
	}

	var instream = fs.createReadStream(wordLists[wordList].file);
	var outstream = new stream();
	var rl = readline.createInterface(instream, outstream);

	var passwordOutput = '';
	var lineNumber = 0;
	rl.on('line', function(line) {
		if(++lineNumber > startEntry) {
			if(lineNumber <= startEntry + wordsPerPage) {
				//toOutput += '<li><a href="/' + encodeURIComponent(line) + '.htm" target="_blank">' + htmlEncode(line) + '</a></li>';
				passwordOutput += calcHashes(line, {
					alwaysHyperlink: true
				});
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

		var wordlistPath = '/wordlists/rules/';

		var passwordsInText = htmlEncode(wordList) + ': ' + htmlEncode(startEntry+1) + ' - ' + htmlEncode(lineNumber - 1);
		var toOutput = '<html><head>' + commonHead + '<title>' + passwordsInText + ' - SpeedHasher.com</title></head><body><div id="content"><h1>Passwords in ' + passwordsInText + '</h1><div class="passwordList">';
		toOutput += passwordOutput;
		toOutput += '</div><a href="' + wordlistPath + htmlEncode(wordList) + '/' + htmlEncode(nextPageNumber) + '/passwords.htm" target="_blank">More Passwords</a>'
		toOutput += commonFooter;
		toOutput += '</div></body></html>'
		res.send(toOutput);
	});
});

function indexPageWordLists() {
	var theOutput = '';

	for(var wordListName in wordLists) {
		var info = wordLists[wordListName];

		theOutput += '<a href="/wordlists/rules/' + htmlEncode(wordListName) + '/0/passwords.htm" target="_blank">' + htmlEncode(info.friendlyName) + '</a>';
		theOutput += '<br>';
	}

	return theOutput;
}

// Landing page
app.get('/', function(req, res, next) {
	res.send(
		'<html><head>' + 
		commonHead + 
		'<title>Hashing Experiment - SpeedHasher.com</title></head>' +
		'<body><div id="content">' + 
		'<h1>Word Lists</h1>' +
		indexPageWordLists() +
		hashPasswordSection() +
		otherPasswords('') +
		commonFooter +
		'</div></body></html>'
	);
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

	// Dynamic Maps
	var possibleInfo = siteMaps[sitemapName];
	if(possibleInfo != null) {
		var maxWords = possibleInfo.lines;
		var thePath = possibleInfo.path;

		for(var i=0; i * wordsPerPage<maxWords; ++i) {
			if(i != 0) {
				res.write('\r\n');
			}
			res.write(websiteRoot + 'wordlists/rules/' + thePath + '/' + i + '/passwords.htm');
		}

		res.send();
		return;
	}

	// Legacy stuff
	if(sitemapName == 'rockyou') {
		var maxWords = 14344391;

		var toOutput = '';

		for(var i=0; i * wordsPerPage<maxWords; ++i) {
			if(i != 0) {
				res.write('\r\n');
			}
			res.write(websiteRoot + 'wordlists/rules/rockyou/' + i + '/passwords.htm');
		}

		res.send();
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

		res.send();
		return;
	}

	next();
});

app.get('/wordlists/:wordList/:pageNumber/passwords.htm', function(req, res, next) {
	var wordList = req.params.wordList;
	var pageNumber = req.params.pageNumber;

	// 301 redirect
	res.redirect(301, '/wordlists/rules/' + encodeURIComponent(wordList) + '/' + encodeURIComponent(pageNumber) + '/passwords.htm');
});

// Mapping for standard hashing
app.get('/:toHash.htm', function(req, res, next) {
	// Grab what we are going to hash
	var toHash = req.params.toHash;

	// 301 redirect to rules
	res.redirect(301, '/rules/' + encodeURIComponent(toHash) + '.htm');
});

// Mapping for rules
app.get('/rules/:toHash', function(req, res, next) {
	// Grab what we are going to hash
	var toHash = req.params.toHash;

	// 301 redirect to rules
	res.redirect(301, '/rules/' + encodeURIComponent(toHash) + '.htm');
});

// Do a wordlist reload
app.get('/reload', function(req, res, next) {
	// Reload the wordlists
	reloadWordlists(function() {
		res.send('Done reloading!');
	});
})

// Error handler
app.use(function(err, req, res, next) {
	winston.error(err);

	// Send a 404
	res.status(404).send('404');
})

// Reload lists
reloadWordlists(function() {
	// Create the HTTP server
	http.createServer(app).listen(config.port, function () {
		winston.info('Server listening on port ' + config.port);
	});

	// Create the HTTPS server
	https.createServer({
		key: fs.readFileSync('creds/creds.key', 'utf8'),
		cert: fs.readFileSync('creds/creds.crt', 'utf8')
	}, app).listen(config.sslPort, function () {
		winston.info('Server listening on SSL port ' + config.sslPort);
	});
});

// Calculates the hashes of a password
function calcHashes(data, options) {
	options = options || {};

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

	if(data.length <= maxIndexSize || options.alwaysHyperlink) {
		outputResHashes += '<tr><th>Input</th><td><a href="/rules/' + encodeURIComponent(data) + hashExtension + '" target="_blank">' + htmlEncode(data) + '</a></td></tr>';
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

// Generates the "hash a password" section
function hashPasswordSection() {
	return	'<h1>Hash a Password</h1>' +
			'<div id="hashPassword"></div>';
}

// Generates a list of suggested other passwords
function otherPasswords(data, options) {
	var outputOtherPasswords = '';
	outputOtherPasswords += '<div>';
	outputOtherPasswords += '<h1>Other Passwords</h1>';

	outputOtherPasswords += '<div class="otherPasswords">';

	if(data.length >= 2) {
		var prevPassword = data.substr(0, data.length - 1);
		
		outputOtherPasswords += calcHashes(prevPassword, {
			alwaysHyperlink: true
		});
	}

	for(var i=0; i<extraChars.length; ++i) {
		var nextPassword = data + extraChars[i];

		outputOtherPasswords += calcHashes(nextPassword, options);
	}

	outputOtherPasswords += '</div>';
	outputOtherPasswords += '</div>';

	return outputOtherPasswords;
}

// Runs a toggle case rule on a word:
function rulesToggleCase(data, options, upto) {
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
		return rulesToggleCase(data, options, upto - 1);
	}

	// Convert our character
	var newChar = myChar.toLowerCase();
	if(newChar == myChar) {
		newChar = myChar.toUpperCase();
	}

	// Grab the new string
	var newString = data.substring(0, upto) + newChar + data.substring(upto + 1);

	// Calculate hashes
	var myOutput = calcHashes(newString, options);

	// Recurse
	myOutput += rulesToggleCase(newString, options, upto - 1);
	myOutput += rulesToggleCase(data, options, upto - 1);

	return myOutput;
}

function rulesLeet(data, options) {
	var myOutput = '';

	myOutput += addIfDifferent(data, data.replace(/i/gi, '1'), options);
	myOutput += addIfDifferent(data, data.replace(/l/gi, '1'), options);
	myOutput += addIfDifferent(data, data.replace(/z/gi, '2'), options);
	myOutput += addIfDifferent(data, data.replace(/e/gi, '3'), options);
	myOutput += addIfDifferent(data, data.replace(/a/gi, '4'), options);
	myOutput += addIfDifferent(data, data.replace(/s/gi, '5'), options);
	myOutput += addIfDifferent(data, data.replace(/b/gi, '6'), options);
	myOutput += addIfDifferent(data, data.replace(/t/gi, '7'), options);
	myOutput += addIfDifferent(data, data.replace(/b/gi, '8'), options);
	myOutput += addIfDifferent(data, data.replace(/g/gi, '9'), options);
	myOutput += addIfDifferent(data, data.replace(/o/gi, '0'), options);
	myOutput += addIfDifferent(data, data.replace(/a/gi, '@'), options);
	myOutput += addIfDifferent(data, data.replace(/s/gi, '$'), options);
	myOutput += addIfDifferent(data, data.replace(/h/gi, '#'), options);
	
	myOutput += addIfDifferent(
		data, data.replace(/a/gi, '@')
					.replace(/s/gi, '$'),
		options
	);
	myOutput += addIfDifferent(
		data, data.replace(/a/gi, '@')
					.replace(/s/gi, '$')
					.replace(/o/gi, '0'),
		options
	);
	myOutput += addIfDifferent(
		data, data.replace(/a/gi, '@')
					.replace(/s/gi, '$')
					.replace(/o/gi, '0')
					.replace(/e/gi, '3'),
		options
	);

	return myOutput;
}

function rulesAppendStuff(data, options) {
	var myOutput = '';

	myOutput += calcHashes(data + '123', options);
	myOutput += calcHashes(data + '1234', options);
	myOutput += calcHashes(data + '123#', options);
	myOutput += calcHashes(data + '123#$', options);
	myOutput += calcHashes(data + '123#$%', options);
	myOutput += calcHashes(data + '1234$', options);
	myOutput += calcHashes(data + '1234$%', options);
	myOutput += calcHashes(data + '!23', options);
	myOutput += calcHashes(data + '!@#', options);
	myOutput += calcHashes(data + '123!@#', options);
	myOutput += calcHashes(data + '123!@#$', options);

	return myOutput;
}

// Returns hashes of string2 if it's different to string1
function addIfDifferent(str1, str2, options) {
	if(str1 == str2) return '';
	return calcHashes(str2, options);
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
	try {
		return crypto.createHash('sha256').update(data).digest('hex');
	} catch(e) {
		return '';
	}
	
}

// Creates a MD5 based on the given data
function md5(data) {
	try {
		return crypto.createHash('md5').update(data).digest('hex');
	} catch(e) {
		return '';
	}
}

// Creates a SHA1 based on the given data
function sha1(data) {
	try {
		return crypto.createHash('sha1').update(data).digest('hex');
	} catch(e) {
		return '';
	}
}
