const { Router } = require('express');
const { userLogin, refreshToken, userLogout } = require('../controllers/authController');

const router = Router();

// routing
router.route('/login').post(userLogin);
router.route('/refresh').get(refreshToken);
router.route('/logout').post(userLogout);

// export
module.exports = router;
