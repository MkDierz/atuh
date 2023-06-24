const { Router } = require('express');
const errorHandler = require('../utils/errorHandler');
const {
  registerField,
  loginField,
  accessTokenField,
  refreshTokenField,
  logoutFields,
  emailField,
  usernameField,
  updateField,
} = require('../utils/validator');
const {
  register,
  login,
  verifyAccessTokenHandler,
  refreshTokenHandler,
  logout,
  emailAvailability,
  usernameAvailability,
} = require('./app');

const router = Router();

router.post('/register', registerField, errorHandler.validation, register);
router.post('/login', loginField, errorHandler.validation, login);
router.post('/verify-token', accessTokenField, errorHandler.validation, verifyAccessTokenHandler);
router.post('/refresh-token', refreshTokenField, errorHandler.validation, refreshTokenHandler);
router.post('/logout', logoutFields, errorHandler.validation, logout);
router.post('/availability/email', emailField, errorHandler.validation, emailAvailability);
router.post('/availability/username', usernameField, errorHandler.validation, usernameAvailability);
router.put('/update', updateField, errorHandler.validation, usernameAvailability);

module.exports = router;
