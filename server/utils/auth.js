const jwt = require("jsonwebtoken");

// set token secret and expiration date
const secret = "mysecretsshhhhhhhh";
const expiration = "2h";

module.exports = {
  authMiddleware: function ({ req }) {
    // token sent via headers
    let token = req.headers.authorization;

    if (req.headers.authorization) {
      token = token.split(" ").pop().trim();
    }

    if (!token) {
      return req;
    }

    // verify token and get user data out of it
    try {
      // jwt verify with our jwt token , secret which should be in dotenv and our expiration which is set to 2hr
      const { data } = jwt.verify(token, secret, { maxAge: expiration });
      req.user = data;
    } catch {
      console.log("Invalid token");
    }

    return req;
  },

  signToken: function ({ username, email, _id }) {
    // payload should not contain sensitive information like passord, address, SS, etc.

    const payload = { username, email, _id };
    // jwt sign the data options object, our secret, and expiration.
    return jwt.sign({ data: payload }, secret, { expiresIn: expiration });
  },
};
