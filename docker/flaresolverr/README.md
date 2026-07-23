# FlareSolverr DDoS-Guard overlay

This image pins the official multi-architecture FlareSolverr `v3.5.0` image by
digest and applies a small, fail-closed source patch at build time. The patch:

- installs pre-document WebDriver fingerprint cleanup;
- runs Linux Chromium headful inside the upstream Xvfb display;
- aligns Xvfb's screen size with Chromium's 1920x1080 window;
- enables Chromium's software WebGL path when hardware acceleration is absent;
- uses a provider-specific DDoS-Guard marker instead of generic `.lds-ring`;
- avoids Cloudflare checkbox key presses for automatic DDoS-Guard challenges;
- performs one bounded refresh when DDoS-Guard's image-cookie bootstrap stalls;
- waits for the observed challenge markers, document readiness, browser
  network idle, and a six-second DDoS-Guard clean window before returning;
- reports the final main-document HTTP status from Chrome instead of assuming 200;
- captures cookies after the caller's post-solve wait and revalidates the page;
- redacts proxy credentials, cookies, HTML, and screenshots from FlareSolverr logs;
- removes temporary authenticated-proxy extensions even if Chrome fails to start; and
- normalizes Chrome's language when the container locale is `C`.

`patch_flaresolverr.py verify /app` and Python compilation run during every
image build. If the official source no longer matches the reviewed v3.5.0
anchors, the build stops and the overlay must be reviewed.

The software WebGL path is explicitly enabled because the container has no
physical GPU. Keep the solver on a trusted, isolated network and do not expose
its API publicly. The included Compose file binds its host port to loopback.
