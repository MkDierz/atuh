const {
  body, header, query, param,
} = require('express-validator');

const emailParam = param('email')
  .exists()
  .notEmpty()
  .withMessage('email required')
  .isEmail()
  .withMessage('valid email required')
  .bail();
const usernameParam = param('username')
  .trim()
  .notEmpty()
  .withMessage('username required')
  .custom((value) => !/\s/.test(value))
  .withMessage('No spaces are allowed in the username')
  .isLength({ min: 4, max: 24 })
  .withMessage('username must be between 4 and 24 characters')
  .isAlphanumeric()
  .withMessage('username must not contain special characters');

const emailField = () => body('email')
  .exists()
  .notEmpty()
  .withMessage('email required')
  .isEmail()
  .withMessage('valid email required')
  .bail();
const usernameField = () => body('username')
  .trim()
  .notEmpty()
  .withMessage('username required')
  .custom((value) => !/\s/.test(value))
  .withMessage('No spaces are allowed in the username')
  .isLength({ min: 4, max: 24 })
  .withMessage('username must be between 4 and 24 characters')
  .isAlphanumeric()
  .withMessage('username must not contain special characters');
const passwordField = () => body('password').isLength({ min: 6 }).withMessage('minimum password length is 6 characters');
const accessTokenQuery = query('accessToken').notEmpty().withMessage('accessToken required');
const accessTokenField = body('accessToken').notEmpty().withMessage('accessToken required');
const refreshTokenField = body('refreshToken').notEmpty().withMessage('refreshToken required');
const authHeader = header('Authorization').notEmpty().withMessage('Authorization required');

const registerField = [emailField(), usernameField(), passwordField()];
const loginField = [emailField(), passwordField()];
const logoutFields = [accessTokenField, refreshTokenField];
const updateField = [
  emailField().optional(),
  usernameField().optional(),
  passwordField().optional(),
  authHeader,
];

module.exports = {
  registerField,
  loginField,
  logoutFields,
  updateField,
  accessTokenField,
  accessTokenQuery,
  refreshTokenField,
  emailField,
  usernameField,
  emailParam,
  usernameParam,
};
