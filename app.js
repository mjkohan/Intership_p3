const express = require("express");
const {pool} = require("./dbConfig");
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
require("dotenv").config();

const app = express();

const initializePassport = require("./passportConfig");

initializePassport(passport);

app.use(express.static(__dirname + '/public'));

app.use(express.urlencoded({extended: false}));
app.set("view engine", "ejs");
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false
    })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

app.get("/", (req, res) => {
    let posts = [];
    pool.query(
        `SELECT * FROM "posts"`, (err, results) => {
            if (err) {
                console.log(err);
            }
            posts.push(results.rows[0]);
            for (let i = 0; i < results.rows.length; i++) {
                posts.push(results.rows[i]);
            }
            res.render("index", {posts});
        }
    );
});

app.get("/posts/:id", (req, res) => {
    pool.query(
        `SELECT * FROM "posts"
        WHERE id = $1`,
        [req.params.id],
        (err, results) => {
            if (err) {
                console.log(err);
            }
            if (results.rows.length > 0) {
                let post = results.rows[0];
                res.render("post", {post});
            } else {
                res.redirect("/");
            }
        }
    );
});

app.get("/users/dashboard/delete/:id", checkNotAuthenticated, (req, res) => {
    pool.query(
        `DELETE FROM "posts"
         WHERE id = $1`, [req.params.id], (err, results) => {
            if (err) {
                console.log(err);
            }
            res.redirect("/users/dashboard");
        }
    );
});

app.get("/users/dashboard/edit/:id", checkNotAuthenticated, (req, res) => {
    pool.query(
        `SELECT * FROM "posts"
        WHERE id = $1`,
        [req.params.id],
        (err, results) => {
            if (err) {
                console.log(err);
            }
            if (results.rows.length > 0) {
                let post = results.rows[0];
                res.render("postedit", {post});
            } else {
                res.redirect("/users/dashboard");
            }
        }
    );
});

app.post("/users/dashboard/edit/:id", async (req, res) => {
    let id = req.params.id;
    let {title, imgurl, bodytext} = req.body;
    pool.query(
        'UPDATE posts SET title = $2 ,imgurl = $3 ,bodytext = $4 where id = $1',
        [id, title, imgurl, bodytext],
        (err, results) => {
            if (err) {
                console.log(err);
            }
            res.redirect("/users/dashboard");
        }
    );
});

app.get("/users/dashboard/postcreate/:author", checkNotAuthenticated, (req, res) => {
    let username = req.params.author;
    res.render("postcreate", {username});
});

app.post("/users/dashboard/postcreate/:author", async (req, res) => {
    let username = req.params.author;
    let {title, imgurl, bodytext} = req.body;
    pool.query(
        `INSERT INTO "posts" (author, title, imgurl, bodytext)
        VALUES ($1, $2, $3, $4)`,
        [username, title, imgurl, bodytext],
        (err, results) => {
            if (err) {
                console.log(err);
            }
            res.redirect("/users/dashboard");
        }
    );
});

app.get("/users/sign-up", checkAuthenticated, (req, res) => {
    res.render("sign-up.ejs");
});

app.get("/users/login", checkAuthenticated, (req, res) => {
    res.render("login.ejs");
});

app.get("/users/dashboard", checkNotAuthenticated, (req, res) => {
    let posts = [];
    let username = req.user.username;
    pool.query(
        `SELECT * FROM "posts"
        WHERE author = $1`,
        [username],
        (err, results) => {
            if (err) {
                console.log(err);
            }
            for (let i = 0; i < results.rows.length; i++) {
                posts.push({
                    id: results.rows[i].id,
                    author: results.rows[i].author,
                    title: results.rows[i].title,
                    imgurl: results.rows[i].imgurl,
                    bodytext: results.rows[i].bodytext
                })
            }
            res.render("dashboard", {posts, username});
        }
    );


});

app.get("/users/logout", (req, res) => {
    req.logout();
    res.render("login", {message: "You have logged out successfully"});
});

app.post("/users/sign-up", async (req, res) => {
    let {username, password, confirmPassWord} = req.body;
    let errors = [];

    if (!username || !password || !confirmPassWord) {
        errors.push({message: "Please enter all fields"});
    }

    if (password.length < 4) {
        errors.push({message: "Password must be a least 4 characters long"});
    }

    if (password !== confirmPassWord) {
        errors.push({message: "Passwords do not match"});
    }

    if (errors.length > 0) {
        res.render("sign-up", {errors, username, password, confirmPassWord});
    } else {
        let hashedPassword = await bcrypt.hash(password, 10);
        pool.query(
            `SELECT * FROM users
        WHERE username = $1`,
            [username],
            (err, results) => {
                if (err) {
                    console.log(err);
                }
                if (results.rows.length > 0) {
                    errors.push({
                        message: "username already signed-up"
                    });
                    return res.render("sign-up",{errors} );
                } else {
                    pool.query(
                        `INSERT INTO users (username, password)
                        VALUES ($1, $2)`,
                        [username, hashedPassword],
                        (err, results) => {
                            if (err) {
                                throw err;
                            }
                            req.flash("success_msg", "You are now signed-up. Please log in");
                            res.redirect("/users/login");
                        }
                    );
                }
            }
        );
    }
});

app.post(
    "/users/login",
    passport.authenticate("local", {
        successRedirect: "/users/dashboard",
        failureRedirect: "/users/login",
        failureFlash: true
    })
);

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect("/users/dashboard");
    }
    next();
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/users/login");
}

module.exports = app;
