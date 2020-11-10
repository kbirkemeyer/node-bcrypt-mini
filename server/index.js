require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const massive = require('massive');

const app = express();

app.use(express.json());

let { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env;

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);

massive({
  connectionString: CONNECTION_STRING,
  ssl: {rejectUnauthorized: false}
}).then(db => {
  app.set('db', db);
});

app.post('/auth/signup', async (req, res, next) => {
  const db = req.app.get('db');
  const {email, password} = req.body;
  const [foundUser] = await db.check_user_exists(email);
  if(foundUser) {
    res.status(403).send("Email already exists")
  }
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);
  const [createdUser] = await db.create_user([email, hashedPassword]);
  req.session.user = {
    id: createdUser.id,
    email: createdUser.email
  }
  res.status(200).send(req.session.user)
});

app.post('/auth/login', async (req, res, next) => {
  const db = req.app.get('db');
  const {email, password} = req.body;
  const [foundUser] = await db.check_user_exists(email);
  if(!foundUser){
    res.status(401).send("Incorrect email or password")
  }
  const authenticated = bcrypt.compareSync(password, foundUser.user_password);
  if(authenticated) {
    req.session.user = {
      id: foundUser.id, 
      email: foundUser.email
    }
    res.status(200).send(req.session.user);
  } else {
    return res.status(401).send("Incorrect email or password");
  }
});

app.post('/auth/logout', (req, res) => {
  req.session.destroy();
  res.sendStatus(200);

app.get('/auth/user', (req, res) => {
  if (req.session.user) {
    res.status(200).send(req.session.user);
  } else {
    res.status(401).send("Please log in")
  }
});

})

app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`);
});