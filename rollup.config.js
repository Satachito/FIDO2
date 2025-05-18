import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import { terser } from 'rollup-plugin-terser';

export default {
  input: 'src/main.js',
  output: {
    file: 'dist/bundle.js',
    format: 'iife', // Immediately Invoked Function Expression (ブラウザ向け)
    name: 'App',
    sourcemap: true,
  },
  plugins: [
    resolve(),
    commonjs(),
    terser(), // 圧縮（省略可）
  ],
};

