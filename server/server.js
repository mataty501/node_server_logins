const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const morgan = require("morgan");
const cors = require("cors");
const helmet = require("helmet");
const User = require("./models/user");
const Token = require("./models/token");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

app.use(express.json());
app.use(morgan("tiny"));
app.use(helmet());
app.use(cors());

mongoose.connect(process.env.MONGODB_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true,
});

const db = mongoose.connection;

db.once("open", () => console.log("database connected :)"));

app.post("/signup", async (req, res, next) => {
    const { username, password } = req.body;
    try {
        const passwordHash = await bcrypt.hash(password, 10);
        const user = new User({
            email: username,
            password: passwordHash,
        });
        await user.save();
        res.status(200);
        res.send(user);
    } catch (error) {
        res.status(400);
        res.send({
            message: error.message,
        });
    }
});

app.post("/login", async (req, res, next) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ email: username });
        if (!user) {
            throw new Error("User doesn't exist");
        }
        const samePassword = await bcrypt.compare(password, user.password);
        if (samePassword) {
            const token = jwt.sign(
                {
                    username: user.email,
                },
                process.env.PRIVATE_KEY,
                {
                    expiresIn: "1m",
                }
            );
            const refreshToken = jwt.sign(
                {
                    username: user.email,
                },
                process.env.REFRESH_KEY,
                {
                    expiresIn: "7d",
                }
            );
            res.status(200);
            const newToken = new Token({
                token: refreshToken
            })
            await newToken.save()
            res.send({
                token: token,
                refreshToken: refreshToken,
            });
        } else {
            throw new Error("Bad credentials");
        }
    } catch (error) {
        res.status(400);
        res.send({
            message: error.message,
        });
    }
});

app.get("/user", (req, res, next) => {
    const token = req.headers.authorization && req.headers.authorization.split(" ")[1];

    const user = jwt.verify(token, process.env.PRIVATE_KEY);
    User.findOne({ email: user.username });
    res.send({
        token,
    });
});

app.get("/token", (req, res, next) => {
    const token =
        req.headers.authorization && req.headers.authorization.split(" ")[1];
    if (Token.findOne({ token: token })) {
        const user = jwt.verify(token, process.env.REFRESH_KEY);
        const newToken = jwt.sign(
            {
                username: user.email,
            },
            process.env.PRIVATE_KEY,
            {
                expiresIn: "1m",
            }
        );
        res.status(200);
        res.send({
            token: newToken
        });
    }
    else {
        res.status(400);
        res.send({
            message: "Invalid token"
        })
    }

})

app.post("/logout", async (req, res, next) => {
    const token =
        req.headers.authorization && req.headers.authorization.split(" ")[1]
    try {
        await Token.findOneAndDelete({ token: token });
        res.status(200)
        res.send({
            message: "successful logout"
        })
    } catch (error) {
        res.status(400);
        res.send({
            message: "bad token"
        })
    }
})

const PORT = process.env.PORT || 2518;
app.listen(PORT, () => {
    console.log(`listening on http://localhost:${PORT}`);
});