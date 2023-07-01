require('dotenv').config();

const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');

const users = require('./models/user');

app.use(express.json());

let refreshTokens = [];

const MongoDBUri = 'mongodb+srv://saikatdevworks:cJQjt0HhOoxexSf6@test-cluster.kfa5qnw.mongodb.net/users?w=majority'
mongoose.connect(MongoDBUri, {
    useNewUrlParser: true, useUnifiedTopology: true
})

app.get('/user/all', (req, res) => {//This is not practical, but kept this for testing
    res.json(users);
});

app.post('/user/token', (req, res) => {
    const refreshToken = req.body.token;
    if (refreshToken == null) return res.sendStatus(401); // If the refresh token is not passed
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403); // If the provided token is not valid
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN, (err, user) => {
      if (err) return res.sendStatus(403);
      const accessToken = generateAccessToken({ name: user.name });
      res.json({ accessToken: accessToken });
    })
});

app.delete('/user/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token);
    res.sendStatus(204);
});

app.post('/user/create', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = { name: req.body.name, password: hashedPassword };

        await users.create(user);
        res.status(201).send('User created');
    }
    catch {
        res.status(500).send('Some internal error');
    }
});

app.post('/user/login', async (req, res) => {
    const userEntity = await users.findOne({ name: req.body.name});
    if (!userEntity) {
        return res.status(400).send('Cannot find user');
    }
    try {
       if(await bcrypt.compare(req.body.password, userEntity.password)) {
            const username = req.body.name;
            const user = { name: username };
            const accessToken = generateAccessToken(user);
            const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN);
            refreshTokens.push(refreshToken);
            res.json({ accessToken: accessToken, refreshToken: refreshToken });
       }
       else {
            res.send('Oops!! something is not correct');
       }
    }
    catch {
        res.status(500).send();
    }
});
  

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN, { expiresIn: '15s' });
}

app.listen(8080, () => {
    console.log('Listening on 8080');
})
