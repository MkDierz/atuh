const { PrismaClient } = require('@prisma/client');
const { Router } = require('express');
const { hashSync, compareSync } = require('bcryptjs');
const { httpError } = require('../config');
const { signToken, verifyAccessToken, verifyRefreshToken } = require('../utils/jwt');
const { tokenBlacklist } = require('../utils/tokenBlacklist');
const errorHandler = require('../utils/errorHandler');
const { exclude } = require('../utils/dro');
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

const prisma = new PrismaClient();
const router = Router();

async function register(req, res, next) {
  const data = { ...req.body };
  let user;
  data.password = hashSync(data.password, 8);
  try {
    user = exclude(await prisma.user.create({ data }), ['password']);
  } catch (e) {
    const errorMessage = errorHandler.prisma(e);
    return next(httpError.Conflict({ detail: errorMessage, field: e.meta.target }));
  }
  return res.send({ ...user, message: 'User created' });
}

async function login(req, res, next) {
  const { email, password } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    return next(httpError.NotFound('User not registered'));
  }

  const checkPassword = compareSync(password, user.password);
  if (!checkPassword) {
    return next(httpError.Unauthorized('Email address or password not valid'));
  }

  const token = signToken(exclude(user, ['password', 'createdAt', 'updatedAt']));
  return res.send({ message: 'authorized', ...token });
}

function verifyAccessTokenHandler(req, res, next) {
  const { accessToken } = req.body;

  if (tokenBlacklist.getBlacklist().includes(accessToken)) {
    return next(httpError.Unauthorized('Invalid credentials'));
  }

  const result = verifyAccessToken(accessToken);

  if (result instanceof httpError.HttpError) {
    return next(result);
  }

  return res.send(result);
}

function refreshTokenHandler(req, res, next) {
  const { refreshToken } = req.body;

  if (tokenBlacklist.getBlacklist().includes(refreshToken)) {
    return next(httpError.Unauthorized('Invalid credentials'));
  }

  const result = verifyRefreshToken(refreshToken);

  if (result instanceof httpError.HttpError) {
    return next(result);
  }

  tokenBlacklist.addBlacklist(refreshToken);
  const token = signToken(exclude(result, ['exp', 'iat']));

  return res.send(token);
}

function logout(req, res) {
  const { accessToken, refreshToken } = req.body;
  tokenBlacklist.addBlacklist(accessToken);
  tokenBlacklist.addBlacklist(refreshToken);
  return res.send({ message: 'User logged out' });
}

async function emailAvailability(req, res) {
  const { email } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    return res.sendStatus(204);
  }

  return res.sendStatus(200);
}

async function usernameAvailability(req, res) {
  const { username } = req.body;

  const user = await prisma.user.findUnique({ where: { username } });

  if (!user) {
    return res.sendStatus(204);
  }

  return res.sendStatus(200);
}

router.post('/register', registerField, errorHandler.validation, register);
router.post('/login', loginField, errorHandler.validation, login);
router.post('/verify-token', accessTokenField, errorHandler.validation, verifyAccessTokenHandler);
router.post('/refresh-token', refreshTokenField, errorHandler.validation, refreshTokenHandler);
router.post('/logout', logoutFields, errorHandler.validation, logout);
router.post('/availability/email', emailField, errorHandler.validation, emailAvailability);
router.post('/availability/username', usernameField, errorHandler.validation, usernameAvailability);
router.put('/update', updateField, errorHandler.validation, usernameAvailability);

module.exports = router;
