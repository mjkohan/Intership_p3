const LocalStrategy = require("passport-local").Strategy;
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");

function initialize(passport) {

    const authenticateUser = (username, password, done) => {
        console.log(username, password);
        pool.query(
            `SELECT * FROM users WHERE username = $1`,
            [username],
            (err, results) => {
                if (err) {
                    throw err;
                }

                if (results.rows.length > 0) {
                    const user = results.rows[0];

                    bcrypt.compare(password, user.password, (err, isMatch) => {
                        if (err) {
                            console.log(err);
                        }
                        if (isMatch) {
                            return done(null, user);
                        } else {
                            //password is incorrect
                            return done(null, false, { message: "Password is incorrect" });
                        }
                    });
                } else {
                    // No user
                    return done(null, false, {
                        message: "No user with that email address"
                    });
                }
            }
        );
    };

    passport.use(
        new LocalStrategy(
            { usernameField: "username", passwordField: "password" },
            authenticateUser
        )
    );

    passport.serializeUser((user, done) => done(null, user.username));

    passport.deserializeUser((username, done) => {
        pool.query(`SELECT * FROM users WHERE username = $1`, [username], (err, results) => {
            if (err) {
                return done(err);
            }
            return done(null, results.rows[0]);
        });
    });
}

module.exports = initialize;