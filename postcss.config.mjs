// Tailwind CSS v4 through PostCSS, which both webpack (`next build --webpack`) and Turbopack
// (`next dev`) run on CSS files.
const config = {
  plugins: {
    "@tailwindcss/postcss": {},
  },
};

export default config;
