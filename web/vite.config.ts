/* eslint-disable import/no-extraneous-dependencies */
import { defineConfig } from 'vite';
import wasmPack from '@authtastic/vite-plugin-wasm-pack';

export default defineConfig({
  plugins: [wasmPack([], ['@authtastic/wasm'], 'index')],
});
