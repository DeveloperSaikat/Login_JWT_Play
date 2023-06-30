require('dotenv').config()

const express = require('express');
const app = express();
const jwt = require('jsonwebtoken')

app.use(express.json());

const posts = [
    {
        username: "Saikat",
        title: "FullStack Engineer"
    },
    {
        username: "Shanks",
        title: "FE Engineer"
    }
]

app.get('/posts', authenticateToken, (req, res) => {
    res.json(posts.filter(post => post.username === req.user.name));
});


function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
  
    jwt.verify(token, process.env.ACCESS_TOKEN, (err, user) => {
      if (err) return res.sendStatus(403);
      console.log(user);
      req.user = user;
      next();
    })
}

app.listen(5000, () => {
    console.log('Listening on port 5000');
})
