function deepMerge(target, source) {
  for (const key in source) {
    const val = source[key];
    if (val && typeof val === 'object') {
      deepMerge(target[key], val);
    } else {
      target[key] = val;
    }
  }
  return target;
}
module.exports = { deepMerge };
