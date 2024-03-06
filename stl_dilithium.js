const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto'); 
const { dilithium } = require('dilithium-crystals');
const { SHA256 } = require('crypto-js');

require('dotenv').config({ path: 'data.env' });

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

const upload = multer({ dest: 'uploads/' });

class Block {
    constructor(index, previousHash, currentTime, stlFile) {
        this.index = index; 
        this.previousHash = previousHash.toString();
        this.currentTime = currentTime;
        this.stlFile = stlFile;
        this.hash = this.calculateHash();
    }

    calculateHash() {
        return SHA256(this.index + this.previousHash + this.currentTime + JSON.stringify(this.stlFile)).toString();
    }
}

class Blockchain {
    constructor() {
        this.chain = [this.createGenesisBlock()];
    }

    createGenesisBlock() {
        return new Block (0, "0", Date.now(), "Genesis Block");
    }

    getLatestBlock() {
        return this.chain[this.chain.length - 1];
    }

    addBlock(newBlock) {
        newBlock.previousHash = this.getLatestBlock().hash;
        if (!newBlock.stlFile) {
            console.error("STL file not provided. Block not added!");
        }
        else {
            newBlock.hash = newBlock.calculateHash();
            this.chain.push(newBlock);
            console.log("Block added.");
        }
    }

    isChainValid() {
        for (let i = 1; i < this.chain.length; i++) {
            const currentBlock = this.chain[i];
            const previousBlock = this.chain[i - 1];

            if (currentBlock.hash !== currentBlock.calculateHash()) {
                return false;
            }

            if (currentBlock.previousHash !== previousBlock.hash) {
                return false;
            }
        }
        return true;
    }
}

const myBlockchain = new Blockchain();

function calculateFileHash(filePath) {
    const fileData = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(fileData).digest('hex');
}

async function signWithDilithium(data, privateKey) {
    const signature = await dilithium.signDetached(Buffer.from(data, 'hex'), Buffer.from(privateKey, 'hex'));
    return signature.toString('hex');
}

async function verifyDilithiumSignature(signature, data, publicKey) {
    return await dilithium.verifyDetached(Buffer.from(signature, 'hex'), Buffer.from(data, 'hex'), Buffer.from(publicKey, 'hex'));
}

function generateKeyPair() {
    return dilithium.keyPair();
}

const users = [
    { username: 'user1', password: 'password1', keys: generateKeyPair() },
    { username: 'user2', password: 'password2', keys: generateKeyPair() }
];

function authenticateUser(username, password) {
    return users.find(user => user.username === username && user.password === password);
}

app.get('/blocks', (req, res) => {
    res.json(myBlockchain.chain);
});

app.post('/upload', upload.single('stlFile'), async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    const user = authenticateUser(username, password);

    if (!user) {
        return res.status(401).send('Authentication failed. Invalid username or password.');
    }

    const stlFilePath = req.file.path;
    const uploadedFileHash = calculateFileHash(stlFilePath);
    const previousBlockHash = myBlockchain.getLatestBlock().hash;

    if (uploadedFileHash !== SHA256(user.keys.publicKey + req.file.filename).toString()) {
        return res.status(400).send('STL file integrity check failed. Block not added.');
    }

    const signature = await signWithDilithium(uploadedFileHash, user.keys.privateKey);
    const isValid = await verifyDilithiumSignature(signature, uploadedFileHash, user.keys.publicKey);

    if (!isValid) {
        return res.status(400).send('Dilithium signature verification failed. Block not added.');
    }

    myBlockchain.addBlock(new Block(1, previousBlockHash, Date.now(), stlFilePath));
    res.send('STL file uploaded and block added.');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}/blocks`);
});

const stlFilePath1 = process.env.STL_FILE_1_PATH || './uploads/model1.stl';
const stlFilePath2 = process.env.STL_FILE_2_PATH || './uploads/model2.stl';

myBlockchain.addBlock(new Block(1, myBlockchain.getLatestBlock().hash, Date.now(), stlFilePath1));
myBlockchain.addBlock(new Block(2, myBlockchain.getLatestBlock().hash, Date.now(), stlFilePath2));
console.log(`Validity of blockchain: ${myBlockchain.isChainValid()}`);
