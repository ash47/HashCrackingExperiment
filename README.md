# HashCrackingWithGoogle
A thought experiment to see if it's possible to leverage google's indexing service to crack hashes.

 - The goal of this project was to make a dynamically generated website, where the pages of the website contain every single password that could exist.
 - Deploy this website and then ask Google to index it.
 - Google will (hopefully) index a large chunk of it.
 - When someone searches for a hash on Google, the password assossiated with that Hash will appear as contents on the website.
 - The hash of every password that Google indexes can be cracked using this website.

The website is deployed here: [http://SpeedHasher.com](http://speedhasher.com)

Let's see how much of it Google indexes.