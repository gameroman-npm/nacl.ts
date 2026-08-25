import { defineConfig } from "tsdown";

export default defineConfig({
  entry: "./src/index.js",
  exports: true,
  dts: true,
});
