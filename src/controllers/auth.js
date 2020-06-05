require("dotenv/config");
const { verify } = require("jsonwebtoken");
const { hash, compare } = require("bcryptjs");
const {
  createAccessToken,
  createRefreshToken,
  sendRefreshToken,
  sendAccessToken,
} = require("../tokens.js");
const { fakeDB } = require("../fakeDB.js");
const { isAuth } = require("../isAuth.js");

// 1. Register a user
const register = async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1. Check if the user exist
    const user = fakeDB.find((user) => user.email === email);

    if (user) throw new Error("User already exist");
    // 2. If not user exist already, hash the password
    const hashedPassword = await hash(password, 10);
    // 3. Insert the user in "database"
    fakeDB.push({
      id: fakeDB.length,
      email,
      password: hashedPassword,
    });

    const accessToken = createAccessToken(user.id);
    const refreshtoken = createRefreshToken(user.id);
    // 4. Store Refreshtoken with user in "db"
    // Could also use different version numbers instead.
    // Then just increase the version number on the revoke endpoint
    user.refreshtoken = refreshtoken;
    sendRefreshToken(res, refreshtoken);
    res.send({ message: "User Created", accessToken });
  } catch (err) {
    res.status(500).send({
      error: err.message,
    });
  }
};

// 2. Login a user
const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1. Find user in array. If not exist send error
    const user = fakeDB.find((user) => user.email === email);
    if (!user) throw new Error("User does not exist");
    // 2. Compare crypted password and see if it checks out. Send error if not
    const valid = await compare(password, user.password);
    if (!valid) throw new Error("Password not correct");
    // 3. Create Refresh- and accessToken
    const accessToken = createAccessToken(user.id);
    const refreshtoken = createRefreshToken(user.id);
    // 4. Store Refreshtoken with user in "db"
    // Could also use different version numbers instead.
    // Then just increase the version number on the revoke endpoint
    user.refreshtoken = refreshtoken;
    // 5. Send token. Refreshtoken as a cookie and accessToken as a regular response
    sendRefreshToken(res, refreshtoken);
    sendAccessToken(res, req, accessToken);
  } catch (err) {
    res.status(500).send({
      error: err.message,
    });
  }
};

// 3. Logout a user
const logout = (req, res) => {
  res.clearCookie("refreshtoken", { path: "/api/refresh_token" });
  // Logic here for also remove refreshtoken from db
  return res.send({
    message: "Logged out",
  });
};

// 4. Protected route
const checkLogin = async (req, res) => {
  try {
    const userId = isAuth(req);
    res.send({ logged: userId !== null });
  } catch (err) {
    res.status(500).send({
      error: err.message,
    });
  }
};

// 5. Get a new access token with a refresh token
const refreshToken = (req, res) => {
  const token = req.cookies.refreshtoken;
  // If we don't have a token in our request
  if (!token) return res.send({ accessToken: "" });
  // We have a token, let's verify it!
  let payload = null;
  try {
    payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
  } catch (err) {
    return res.send({ accessToken: "" });
  }
  // token is valid, check if user exist
  const user = fakeDB.find((user) => user.id === payload.userId);
  if (!user) return res.send({ accessToken: "" });
  // user exist, check if refreshtoken exist on user
  if (user.refreshtoken !== token) return res.send({ accessToken: "" });
  // token exist, create new Refresh- and accessToken
  const accessToken = createAccessToken(user.id);
  const refreshtoken = createRefreshToken(user.id);
  // update refreshtoken on user in db
  // Could have different versions instead!
  user.refreshtoken = refreshtoken;
  // All good to go, send new refreshtoken and accessToken
  sendRefreshToken(res, refreshtoken);
  return res.send({ accessToken });
};

module.exports = {
  register,
  login,
  logout,
  checkLogin,
  refreshToken,
};
