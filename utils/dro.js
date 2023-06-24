function exclude(data, keys) {
  const returnValue = { ...data };
  keys.forEach((key) => {
    delete returnValue[key];
  });
  return returnValue;
}

function clean(data) {
  const obj = { ...data };
  Object.keys(obj).forEach((key) => {
    if ((obj[key] === null) || (obj[key] === undefined)) {
      delete obj[key];
    }
  });
  return obj;
}

module.exports = {
  exclude,
  clean,
};
