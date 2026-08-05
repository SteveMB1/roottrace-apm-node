"use strict";

const js = require("@eslint/js");

const nodeGlobals = {
  require: "readonly",
  module: "writable",
  exports: "writable",
  process: "readonly",
  console: "readonly",
  Buffer: "readonly",
  URL: "readonly",
  setInterval: "readonly",
  clearInterval: "readonly",
  setTimeout: "readonly",
  clearTimeout: "readonly",
  setImmediate: "readonly",
  __dirname: "readonly",
  __filename: "readonly",
  global: "readonly",
  globalThis: "readonly",
  // WHATWG globals shipped with Node 18+, the package's engines floor
  fetch: "readonly",
  Headers: "readonly",
  Request: "readonly",
  Response: "readonly",
};

module.exports = [
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "commonjs",
      globals: nodeGlobals,
    },
  },
  {
    ignores: ["node_modules/", "coverage/"],
  },
];
