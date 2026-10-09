I wanted to see what actually happens between login, access-token expiry, and refresh—without copying tokens between curl commands.

So I built a small JWT Playground you can run locally in your browser.

You can:
• Inspect access and refresh tokens side by side
• Decode a JWT's header and claims
• Watch an access token expire in 20 seconds
• Refresh it and see both tokens rotate
• Reuse an old refresh token and watch the server reject it
• Compare 401 vs 403, try different roles, and tamper with a token
• Inspect the actual request and response for every step

One detail that becomes clear when you try it: in this demo, logout revokes the refresh token, but the access token still works until it expires.

It runs on Python's standard library with plain HTML, CSS, and JavaScript. No dependencies or frontend build. It's a learning playground, not production authentication code.

Try it:
git clone https://github.com/prashant676a/jwt_demo.git
cd jwt_demo
python3 server.py

Then open http://127.0.0.1:8000 in your browser.

Code: https://github.com/prashant676a/jwt_demo

If you're learning JWTs or explaining them to someone else, give it a try. What authentication flow would you add next?

#JWT #Python #WebDevelopment #Authentication #LearningInPublic

---
Attach `docs/jwt-playground.png` to the post. Suggested image alt text: JWT Playground in a browser, with login controls, decoded access-token claims, a refresh token, and an API request/response trace.
