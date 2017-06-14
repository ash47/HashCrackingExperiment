# Hash Cracking Experiment
A thought experiment to see if it's possible to leverage google's indexing service to crack hashes.

 - The goal of this project was to make a dynamically generated website, where the pages of the website contain every single password that could exist.
 - Deploy this website and then ask Google to index it.
 - Google will (hopefully) index a large chunk of it.
 - When someone searches for a hash on Google, the password assossiated with that Hash will appear as contents on the website.
 - The hash of every password that Google indexes can be cracked using this website.
 - As an example, type the following hash into Google to "crack" it: [07fc37bfba617b804731ce083b72d87f](https://www.google.com.au/search?q=07fc37bfba617b804731ce083b72d87f)
 - The above example was working at the time of writing this.

The website is deployed here: [http://SpeedHasher.com](http://speedhasher.com)

You can view the current indexing progress here: [SpeedHasher.com on Google](https://www.google.com.au/search?q=site%3Aspeedhasher.com)

Looks like Yandex loves the website: [SpeedHasher.com on Yandex](https://yandex.com/search/?text=site%3Aspeedhasher.com)

Let's see how much of it Google indexes.