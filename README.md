# BeamHash - Beam Implementation
nodejs native binding to check for valid Beamhash solutions

# Dependencies
````
sudo apt-get install build-essential libsodium-dev libboost-system-dev
````

# Usage
````javascript
var bhv = require('bindings')('beamhashverify.node');

var version = 2; //use BeamHashII
var header = new Buffer(..., 'hex');
var solution = new Buffer(..., 'hex'); //do not include byte size preamble "fd4005"

bhv.verify(header, nonce, solution, version); //omitting version will default to BeamHashIII
//returns boolean
````

# Test Suite:
````
sudo npm install -g mocha
npm install
mocha
````

