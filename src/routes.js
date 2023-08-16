const { Router } = require('express');
const errorHandler = require('../utils/errorHandler');
const {
  registerField,
  loginField,
  accessTokenQuery,
  refreshTokenField,
  logoutFields,
  updateField,
  emailParam,
  usernameParam,
} = require('../utils/validator');
const {
  register,
  login,
  verifyAccessTokenHandler,
  refreshTokenHandler,
  logout,
  emailAvailability,
  usernameAvailability,
  update,
} = require('./app');

const router = Router();

router.post('/register', registerField, errorHandler.validation, register);
router.post('/login', loginField, errorHandler.validation, login);
router.post('/refresh-token', refreshTokenField, errorHandler.validation, refreshTokenHandler);
router.post('/logout', logoutFields, errorHandler.validation, logout);

router.get('/verify-token', accessTokenQuery, errorHandler.validation, verifyAccessTokenHandler);
router.get('/availability/email/:email', emailParam, errorHandler.validation, emailAvailability);
router.get('/availability/username/:username', usernameParam, errorHandler.validation, usernameAvailability);

router.put('/update', updateField, errorHandler.validation, update);

module.exports = router;
