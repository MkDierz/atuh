function exclude(data, keys) {
  const returnValue = { ...data };
  keys.forEach((key) => {
    delete returnValue[key];
  });
  return returnValue;
}

module.exports = {
  exclude,
};
