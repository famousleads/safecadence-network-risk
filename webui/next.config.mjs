/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The Next.js app is served standalone for development. In production
  // we rewrite /api/* to the FastAPI backend so the React app can reach
  // the existing endpoints without CORS gymnastics.
  async rewrites() {
    const backend = process.env.SAFECADENCE_BACKEND_URL || "http://localhost:8765";
    return [
      { source: "/api/:path*", destination: `${backend}/api/:path*` },
    ];
  },
};

export default nextConfig;
