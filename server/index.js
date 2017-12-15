require('dotenv').config()
const express = require('express')
    , bodyParser = require('body-parser')
    , cors = require('cors')
    , session = require('express-session')
    , passport = require('passport')
    , Auth0Strategy = require('passport-auth0')
    , massive = require('massive')

const app = express();

app.use(bodyParser.json())
app.use(cors())

massive(process.env.DB_CONNECTION).then(db => {
    app.set('db', db)
})

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true
}))

app.use(express.static(__dirname+ '/../build'))

app.use(passport.initialize());
app.use(passport.session());

passport.use(new Auth0Strategy({
    domain: process.env.AUTH_DOMAIN,
    clientID: process.env.AUTH_CLIENT_ID,
    clientSecret: process.env.AUTH_CLIENT_SECRET,
    callbackURL: process.env.AUTH_CALLBACK
}, function (accessToken, refreshToken, extraParams, profile, done) {
    const db = app.get('db')
    let userData = profile._json
    let authid = userData.user_id.split('|')[1]

    db.find_user([authid]).then(user => {
        if (user[0]) {
            return done(null, user[0].id)
        } else {
            db.create_user([userData.name, userData.email, userData.picture, authid])
                .then(user => {
                    return done(null, user[0].id)
                })
        }
    })
}))

app.get('/auth', passport.authenticate('auth0'))
app.get('/auth/callback', passport.authenticate('auth0', {
    successRedirect: process.env.AUTH_SUCCESS,
    failureRedirect: process.env.AUTH_FAILURE
}))

passport.serializeUser(function (ID, done) {
    done(null, ID) // usually save user id from db to session (happens once on login)
})

passport.deserializeUser(function (ID, done) {
    // ID == 1
    const db = app.get('db')
    db.find_user_session([ID]).then(user => {
        done(null, user[0]) //happens everytime an endpoint is hit
    })
})

app.get('/auth/me', function (req, res, next) {
    if (!req.user) {
        res.status(401).send('LOG IN REQUIRED')
    } else {
        res.status(200).send(req.user)
    }
})

app.get('/auth/logout', function (req, res, next) {
    req.logout()
    res.redirect(process.env.AUTH_FAILURE)
})

app.listen(process.env.SERVER_PORT, () => { console.log(`Server listening on port ${process.env.SERVER_PORT}`) })