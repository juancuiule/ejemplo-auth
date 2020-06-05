require("dotenv/config");
const express = require("express");
const cookieParser = require("cookie-parser");
const authController = require("./controllers/auth");
const cors = require('cors');

const app = express();

app.use(
  cors({
    origin: 'http://localhost:3000',
    credentials: true,
  }),
);

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use("/auth", express.static("public/auth"));
app.use("/experimento-a", express.static("public/experimento-a"));
app.use("/experimento-b", express.static("public/experimento-b"));

app.post("/api/register", authController.register);
app.post("/api/login", authController.login);
app.post("/api/logout", authController.logout);
app.get("/api/check", authController.checkLogin);
app.post("/api/refresh_token", authController.refreshToken);

app.use("/", (req, res) => { res.redirect('/auth') });

app.listen(process.env.PORT, () =>
  console.log(`Server listening on port ${process.env.PORT}!`)
);

