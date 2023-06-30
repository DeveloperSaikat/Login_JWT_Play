require('dotenv').config();

const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

app.use(express.json());

let refreshTokens = [];
const users = [];

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

        users.push(user);
        res.status(201).send();
    }
    catch {
        res.status(500).send();
    }
});

app.post('/user/login', async (req, res) => {
    const userEntity = users.find(user => user.name === req.body.name);
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
