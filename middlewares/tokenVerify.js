const { verify } = require('jsonwebtoken');

const tokenVerify = (req, res, next) => {
  const { authorization, Authorization } = req.headers;

  const authHeader = authorization || Authorization;

  !authHeader ? res.status(401).json({ message: 'Unauthorized' }) : next();

  // split its token from bearer token
  const token = authHeader.split(' ')[1];

  // verify the token
  verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decode) => {
    if (err) {
      res.status(403).json({ message: 'Forbidden' });
      return;
    }

    req.email = decode.email;
    req.role = decode.role;
    next();
  });
};

module.exports = { tokenVerify };
