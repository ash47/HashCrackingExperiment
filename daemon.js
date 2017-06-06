// Crypto Imports
const lmhash = require('smbhash').lmhash;
const nthash = require('smbhash').nthash;
const crypto = require('crypto');

// IO Imports
const fs = require('fs');
const readline = require('readline');
const stream = require('stream');

// Webserver Imports
const express = require('express');
const app = express();

// Config
const serverPort = 8080;
const hashExtension = '.htm';
const wordsPerPage = 25;

// Used for generation of other URLs
const allowedChars = /^[A-Za-z0-9 !@#$%^&*()-_=+\[\]{}|\\;:'"?/,.<>`~]+$/g;
const extraChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 !@#$%^&*()-_=+[]{}|\\;:\'"?/,.<>`~';

// List of wordlists we support
const wordLists = {
	rockyou: __dirname + '/wordlists/rockyou.txt'
};

// Read in the common headers
const commonHead = fs.readFileSync(__dirname + '/lib/common_head.htm');

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

	var toOutput = '<html><head>' + commonHead + '</head><body><h1>Passwords in ' + wordList + ': ' + startEntry + ' - ' + (nextPasswordsPage - 1) + '</h1><ul>'
	var lineNumber = 0;
	rl.on('line', function(line) {
		if(++lineNumber > startEntry) {
			if(lineNumber <= startEntry + wordsPerPage) {
				toOutput += '<li><a href="/' + encodeURIComponent(line) + '.htm" target="_blank">' + htmlEncode(line) + '</a></li>';
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

		toOutput += '</ul><a href="/wordlists/' + wordList + '/' + nextPasswordsPage + '/passwords.htm" target="_blank">More Passwords</a>'
		toOutput += '</body></html>'
		res.end(toOutput);
	});
});

// Mapping for hashes
app.use(function(req, res, next) {
	var url = req.url;

	if(url == '/') {
		// Root page
		res.end('<html><head>' + commonHead + '</head><body><h1>wordLists</h1><a href="/wordlists/rockyou/0/passwords.htm">RockYou</a>' + otherPasswords('') + '</body></html>');
		return;
	}

	if(url.lastIndexOf(hashExtension) == url.length - hashExtension.length) {
		var toMatch;

		// Ensure it is valid
		try {
			toMatch = decodeURIComponent(url.substr(1, url.length - hashExtension.length - 1));
		} catch(e) {
			next();
			return;
		}

		if(!allowedChars.test(toMatch)) {
			next();
			return;
		}

		res.status(200);

		var outputResHashes = '';

		var lmHash = lmhash(toMatch).toLowerCase();
		var ntHash = nthash(toMatch).toLowerCase();

		outputResHashes += '<table class="table table-striped">';
		outputResHashes += '<tr><th>Input</th><td>' + htmlEncode(toMatch) + '</td></tr>';
		outputResHashes += '<tr><th>NTLM</th><td>' + lmHash + ':' + ntHash + '</td></tr>';
		outputResHashes += '<tr><th>NTLM (no LM)</th><td>aad3b435b51404eeaad3b435b51404ee:' + ntHash + '</td></tr>';
		outputResHashes += '<tr><th>MD5</th><td>' + md5(toMatch) + '</td></tr>';
		outputResHashes += '<tr><th>SHA-1</th><td>' + sha1(toMatch) + '</td></tr>';
		outputResHashes += '<tr><th>SHA-256</th><td>' + sha256(toMatch) + '</td></tr>';
		outputResHashes += '</table>';

		var outputBody = '<html><head>' + commonHead + '</head><body>';
		outputBody += outputResHashes;
		outputBody += otherPasswords(toMatch);
		outputBody += '</body></html>';

		res.end(outputBody);
		return;
	}

	next();
});

app.listen(serverPort, function () {
	console.log('Server listening on port ' + serverPort);
});

// Generates a list of suggested other passwords
function otherPasswords(data) {
	var outputOtherPasswords = '';
	outputOtherPasswords += '<div>';
	outputOtherPasswords += '<h1>Other Passwords</h1>';

	outputOtherPasswords += '<ul>';

	if(data.length >= 2) {
		var prevPassword = data.substr(0, data.length - 1);
		outputOtherPasswords += '<li><a href="/' + encodeURIComponent(prevPassword) + '.htm" target="_blank">' + htmlEncode(prevPassword) + '</a></li>'
	}

	for(var i=0; i<extraChars.length; ++i) {
		var nextPassword = data + extraChars[i];

		outputOtherPasswords += '<li><a href="/' + encodeURIComponent(nextPassword) + '.htm" target="_blank">' + htmlEncode(nextPassword) + '</a></li>'
	}

	outputOtherPasswords += '</ul>';
	outputOtherPasswords += '</div>';

	return outputOtherPasswords;
}

// HTML Encodes a string
function htmlEncode(data) {
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
