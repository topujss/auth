const User = require('../models/User');
const asyncHandler = require('express-async-handler'); // use with those has api call not to all
const { compareSync } = require('bcrypt');
const { sign, verify } = require('jsonwebtoken');
// to make accessToken by node - node > require('crypto').randomBytes(64).toString('hex')

/**
 * @error you must check!
 */

/**
 * @desc user login feature
 * @route POST /login
 * @access PUBLIC
 */
const userLogin = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // validate email and password
  !email || !password ? res.status(200).json({ message: 'All fields are required' }) : res.status(404);

  // find user by email
  const loginUser = await User.findOne({ email: email });
  !loginUser ? res.status(404).json({ message: 'User not found' }) : res.status(200);

  // match the password against the user's password
  const matchPassword = compareSync(password, loginUser.password);
  !matchPassword ? res.status(404).json({ message: 'Password does not match' }) : res.status(200);

  // Now that the user is loggedin by server we can validate by refresh token like otp
  const refreshToken = sign(
    {
      email: loginUser.email,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN,
    }
  );

  res.cookie('refresh_token', refreshToken, {
    httpOnly: true,
    secure: process.env.APP_ENV === 'development' ? false : true,
    maxAge: 1000 * 60 * 60 * 24 * 7, // when will  refresh token cookie expire?
  });

  // validate by the access token - error happening after these
  const accessToken = sign(
    {
      email: loginUser.email,
      role: loginUser.role,
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN,
    }
  );

  // send token to cookie
  res.cookie('access_token', accessToken, {
    httpOnly: true,
    secure: process.env.APP_ENV === 'development' ? false : true,
    maxAge: 1000 * 30, // when will cookie expire?
  });

  res.status(200).json({ token: accessToken });
});

/**
 * @desc refresh token request
 * @route GET /refresh
 * @access PUBLIC
 */
const refreshToken = (req, res) => {
  // get token from cookie
  const cookies = req.cookies;

  !cookies?.refresh_token ? res.status(400).json({ message: 'Invalid token request' }) : res.status(200);

  const token = cookies.refresh_token;

  // verify with jwt verification
  verify(
    token,
    process.env.REFRESH_TOKEN_SECRET,
    asyncHandler(async (err, decode) => {
      err ? res.status(401).json({ message: 'Not a valid token' }) : res.status(200);

      const tokenUser = await User.findOne({ email: decode.email });
      !tokenUser ? res.status(404).json({ message: 'User not Found' }) : res.status(200);

      // validate by the access token
      const accessToken = sign(
        {
          email: tokenUser.email,
          role: tokenUser.role,
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
          expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN,
        }
      );

      res.status(200).json({ token: accessToken });
    })
  );
};

/**
 * @desc Logout the current user
 * @route POST /logout
 * @access PUBLIC
 */
const userLogout = (req, res) => {
  const isCookies = req.cookies;

  !isCookies?.refresh_token ? res.status(401).json({ message: 'Invalid logout request' }) : res.status(200);

  res
    .clearCookie('refresh_token', {
      httpOnly: true,
      secure: process.env.APP_ENV === 'development' ? false : true,
    })
    .status(200)
    .json({ message: 'Logged out' });
};

module.exports = {
  userLogin,
  userLogout,
  refreshToken,
};
