const FILES = {
  all: { path: "all_universal.txt", type: "text/plain; charset=utf-8" },
  vless: { path: "vless_universal.txt", type: "text/plain; charset=utf-8" },
  hy2: { path: "hysteria2.txt", type: "text/plain; charset=utf-8" },
  ss: { path: "shadowsocks.txt", type: "text/plain; charset=utf-8" },
  stats: { path: "state/stats.json", type: "application/json; charset=utf-8" },
  meta: { path: "state/meta.json", type: "application/json; charset=utf-8" },
  history: { path: "state/history.json", type: "application/json; charset=utf-8" },
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return new Response("ok\n", {
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }

    if (!env.SUB_KEY || !env.GH_TOKEN) {
      return new Response("Worker is not configured\n", { status: 500 });
    }

    const parts = url.pathname.split("/").filter(Boolean);
    if (parts[0] !== env.SUB_KEY) {
      return new Response("Not found\n", { status: 404 });
    }

    const file = FILES[parts[1]];
    if (!file) {
      return new Response("Not found\n", { status: 404 });
    }

    const repo = env.GITHUB_REPO || "BarqDev1/vless-aggregator";
    const branch = env.GITHUB_BRANCH || "main";
    const apiUrl =
      `https://api.github.com/repos/${repo}/contents/${file.path}?ref=${encodeURIComponent(branch)}`;

    let upstream;
    try {
      upstream = await fetch(apiUrl, {
        headers: {
          Authorization: `Bearer ${env.GH_TOKEN}`,
          Accept: "application/vnd.github.raw+json",
          "X-GitHub-Api-Version": "2022-11-28",
          "User-Agent": "vpn-aggregator-worker",
        },
      });
    } catch {
      return new Response("Upstream request failed\n", { status: 502 });
    }

    if (!upstream.ok) {
      return new Response(`Upstream error: ${upstream.status}\n`, { status: 502 });
    }

    return new Response(upstream.body, {
      headers: {
        "content-type": file.type,
        "cache-control": "public, max-age=60",
        "x-content-type-options": "nosniff",
        "profile-title": env.PROFILE_TITLE || "BarqDev Multi-Protocol VPN",
        "profile-update-interval": env.PROFILE_UPDATE_INTERVAL || "0.5",
        "support-url":
          env.SUPPORT_URL || "https://github.com/BarqDev1/vless-aggregator/issues",
      },
    });
  },
};
