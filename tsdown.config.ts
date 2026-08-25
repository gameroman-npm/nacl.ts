import { defineConfig } from "tsdown";

export default defineConfig({
  entry: {
    index: "./src/nacl.js",
    fast: "./src/nacl-fast.js",
    util: "./src/nacl-util.js",
  },
  exports: true,
  dts: true,
});
