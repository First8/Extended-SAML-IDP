require('dotenv').config();

const required = ['KEYCLOAK_USER', 'KEYCLOAK_PASSWORD'];
const missing = required.filter(k => !process.env[k]);
if (missing.length > 0) {
    console.error(`Missing required environment variables: ${missing.join(', ')}`);
    console.error('Set them in src/test/e2e/.env or as environment variables.');
    console.error('See src/test/e2e/.env.example for the expected format.');
    process.exit(1);
}

module.exports = {
    baseUrl:  process.env.KEYCLOAK_URL  || 'http://localhost:8081',
    realm:    process.env.KEYCLOAK_REALM || 'master',
    username: process.env.KEYCLOAK_USER,
    password: process.env.KEYCLOAK_PASSWORD,
};
