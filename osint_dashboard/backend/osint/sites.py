"""
Site catalogue for username / handle enumeration (Sherlock-style).

Each entry:
  name        : display name
  url         : profile URL template, {} is replaced by the handle
  check       : "status"  -> exists if HTTP 200 AND the handle appears on the
                             page (guards against SPA soft-404s), or a hard 404
                             on the missing page.
                "message" -> account does NOT exist if `absence` text is in body.
  absence     : substring that indicates the profile is missing (for "message")
  reliable    : set False for JS-only sites whose real/missing pages are
                byte-identical over plain HTTP -> reported as "check manually"
                instead of a (false) hit.
  cat         : category for grouping in the UI

Detection tiers (see username_osint._check_site):
  hard-404  -> not_found        |  anti-bot page -> blocked/manual
  200+handle present -> found   |  200 w/o handle -> not_found
"""

SITES = [
    # ---------------- Developer / tech ----------------
    {"name": "GitHub", "url": "https://github.com/{}", "check": "status", "cat": "dev"},
    {"name": "GitHub Gist", "url": "https://gist.github.com/{}", "check": "status", "cat": "dev"},
    {"name": "GitLab", "url": "https://gitlab.com/{}", "check": "status", "cat": "dev"},
    {"name": "Bitbucket", "url": "https://bitbucket.org/{}/", "check": "status", "cat": "dev"},
    {"name": "SourceForge", "url": "https://sourceforge.net/u/{}/profile/", "check": "status", "cat": "dev"},
    {"name": "Docker Hub", "url": "https://hub.docker.com/u/{}", "check": "status", "cat": "dev"},
    {"name": "PyPI", "url": "https://pypi.org/user/{}/", "check": "status", "cat": "dev"},
    {"name": "npm", "url": "https://www.npmjs.com/~{}", "check": "status", "cat": "dev"},
    {"name": "RubyGems", "url": "https://rubygems.org/profiles/{}", "check": "status", "cat": "dev"},
    {"name": "Packagist", "url": "https://packagist.org/users/{}/", "check": "status", "cat": "dev"},
    {"name": "Replit", "url": "https://replit.com/@{}", "check": "status", "cat": "dev"},
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={}", "check": "message",
     "absence": "No such user.", "cat": "dev"},
    {"name": "Keybase", "url": "https://keybase.io/{}", "check": "status", "cat": "dev"},
    {"name": "Codepen", "url": "https://codepen.io/{}", "check": "status", "cat": "dev"},
    {"name": "Kaggle", "url": "https://www.kaggle.com/{}", "check": "status", "cat": "dev"},
    {"name": "Dev.to", "url": "https://dev.to/{}", "check": "status", "cat": "dev"},
    {"name": "Hashnode", "url": "https://hashnode.com/@{}", "check": "status", "reliable": False, "cat": "dev"},
    {"name": "HackerOne", "url": "https://hackerone.com/{}", "check": "status", "cat": "dev"},
    {"name": "Bugcrowd", "url": "https://bugcrowd.com/{}", "check": "status", "cat": "dev"},
    {"name": "LeetCode", "url": "https://leetcode.com/{}/", "check": "status", "cat": "dev"},
    {"name": "Codewars", "url": "https://www.codewars.com/users/{}", "check": "status", "cat": "dev"},
    {"name": "Exercism", "url": "https://exercism.org/profiles/{}", "check": "status", "cat": "dev"},
    {"name": "HackerEarth", "url": "https://www.hackerearth.com/@{}", "check": "status", "cat": "dev"},
    {"name": "TryHackMe", "url": "https://tryhackme.com/p/{}", "check": "status", "reliable": False, "cat": "dev"},
    {"name": "Wordpress", "url": "https://profiles.wordpress.org/{}/", "check": "status", "cat": "dev"},

    # ---------------- Social ----------------
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}", "check": "message",
     "absence": "Sorry, nobody on Reddit goes by that name", "cat": "social"},
    {"name": "Instagram", "url": "https://www.instagram.com/{}/", "check": "status",
     "reliable": False, "cat": "social"},
    {"name": "X / Twitter", "url": "https://x.com/{}", "check": "status",
     "reliable": False, "cat": "social"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{}", "check": "message",
     "absence": "Couldn't find this account", "cat": "social"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{}/", "check": "message",
     "absence": "<title></title>", "cat": "social"},
    {"name": "Facebook", "url": "https://www.facebook.com/{}", "check": "status",
     "reliable": False, "cat": "social"},
    {"name": "Snapchat", "url": "https://www.snapchat.com/add/{}", "check": "status", "cat": "social"},
    {"name": "Threads", "url": "https://www.threads.net/@{}", "check": "status",
     "reliable": False, "cat": "social"},
    {"name": "Bluesky", "url": "https://bsky.app/profile/{}.bsky.social", "check": "status",
     "reliable": False, "cat": "social"},
    {"name": "VK", "url": "https://vk.com/{}", "check": "status", "cat": "social"},
    {"name": "OK.ru", "url": "https://ok.ru/{}", "check": "status", "cat": "social"},
    {"name": "Tumblr", "url": "https://{}.tumblr.com", "check": "status", "cat": "social"},
    {"name": "Mastodon (mastodon.social)", "url": "https://mastodon.social/@{}", "check": "status", "cat": "social"},
    {"name": "Minds", "url": "https://www.minds.com/{}/", "check": "status", "cat": "social"},
    {"name": "Gab", "url": "https://gab.com/{}", "check": "status", "cat": "social"},
    {"name": "Quora", "url": "https://www.quora.com/profile/{}", "check": "status", "cat": "social"},

    # ---------------- Media / content / creative ----------------
    {"name": "YouTube", "url": "https://www.youtube.com/@{}", "check": "status", "cat": "media"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{}", "check": "status", "cat": "media"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{}", "check": "status", "cat": "media"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{}", "check": "status",
     "reliable": False, "cat": "media"},
    {"name": "Bandcamp", "url": "https://{}.bandcamp.com", "check": "status", "cat": "media"},
    {"name": "Mixcloud", "url": "https://www.mixcloud.com/{}/", "check": "status", "reliable": False, "cat": "media"},
    {"name": "Last.fm", "url": "https://www.last.fm/user/{}", "check": "status", "cat": "media"},
    {"name": "Vimeo", "url": "https://vimeo.com/{}", "check": "status", "cat": "media"},
    {"name": "Dailymotion", "url": "https://www.dailymotion.com/{}", "check": "status", "cat": "media"},
    {"name": "Rumble", "url": "https://rumble.com/user/{}", "check": "status", "cat": "media"},
    {"name": "Flickr", "url": "https://www.flickr.com/people/{}", "check": "status", "cat": "media"},
    {"name": "500px", "url": "https://500px.com/p/{}", "check": "status", "cat": "media"},
    {"name": "Imgur", "url": "https://imgur.com/user/{}", "check": "status", "cat": "media"},
    {"name": "Dribbble", "url": "https://dribbble.com/{}", "check": "status", "cat": "media"},
    {"name": "Behance", "url": "https://www.behance.net/{}", "check": "status", "cat": "media"},
    {"name": "DeviantArt", "url": "https://www.deviantart.com/{}", "check": "status", "cat": "media"},
    {"name": "Newgrounds", "url": "https://{}.newgrounds.com", "check": "status", "cat": "media"},
    {"name": "Redbubble", "url": "https://www.redbubble.com/people/{}/shop", "check": "status", "cat": "media"},
    {"name": "Medium", "url": "https://medium.com/@{}", "check": "status", "cat": "media"},
    {"name": "Slideshare", "url": "https://www.slideshare.net/{}", "check": "status", "cat": "media"},

    # ---------------- Gaming ----------------
    {"name": "Steam", "url": "https://steamcommunity.com/id/{}", "check": "message",
     "absence": "The specified profile could not be found", "cat": "gaming"},
    {"name": "Steam (groups)", "url": "https://steamcommunity.com/groups/{}", "check": "message",
     "absence": "No group could be retrieved", "cat": "gaming"},
    {"name": "Chess.com", "url": "https://www.chess.com/member/{}", "check": "status", "cat": "gaming"},
    {"name": "Lichess", "url": "https://lichess.org/@/{}", "check": "status", "cat": "gaming"},
    {"name": "itch.io", "url": "https://{}.itch.io", "check": "status", "cat": "gaming"},
    {"name": "GameJolt", "url": "https://gamejolt.com/@{}", "check": "status", "cat": "gaming"},
    {"name": "Speedrun.com", "url": "https://www.speedrun.com/users/{}", "check": "status", "cat": "gaming"},
    {"name": "Roblox", "url": "https://www.roblox.com/users/profile?username={}", "check": "status",
     "reliable": False, "cat": "gaming"},
    {"name": "Osu!", "url": "https://osu.ppy.sh/users/{}", "check": "status", "cat": "gaming"},
    {"name": "Fandom / Wikia", "url": "https://community.fandom.com/wiki/User:{}", "check": "status", "cat": "gaming"},

    # ---------------- Marketplace / creator / misc ----------------
    {"name": "Patreon", "url": "https://www.patreon.com/{}", "check": "status", "cat": "misc"},
    {"name": "Ko-fi", "url": "https://ko-fi.com/{}", "check": "status", "cat": "misc"},
    {"name": "Buymeacoffee", "url": "https://www.buymeacoffee.com/{}", "check": "status", "cat": "misc"},
    {"name": "Gumroad", "url": "https://{}.gumroad.com", "check": "status", "cat": "misc"},
    {"name": "Linktree", "url": "https://linktr.ee/{}", "check": "status", "cat": "misc"},
    {"name": "AllMyLinks", "url": "https://allmylinks.com/{}", "check": "status", "cat": "misc"},
    {"name": "Gravatar", "url": "https://gravatar.com/{}", "check": "status", "cat": "misc"},
    {"name": "About.me", "url": "https://about.me/{}", "check": "status", "cat": "misc"},
    {"name": "Wattpad", "url": "https://www.wattpad.com/user/{}", "check": "status", "cat": "misc"},
    {"name": "Goodreads", "url": "https://www.goodreads.com/{}", "check": "status", "cat": "misc"},
    {"name": "Letterboxd", "url": "https://letterboxd.com/{}/", "check": "status", "cat": "misc"},
    {"name": "Trakt", "url": "https://trakt.tv/users/{}", "check": "status", "cat": "misc"},
    {"name": "Untappd", "url": "https://untappd.com/user/{}", "check": "status", "cat": "misc"},
    {"name": "Product Hunt", "url": "https://www.producthunt.com/@{}", "check": "status", "cat": "misc"},
    {"name": "Trello", "url": "https://trello.com/{}", "check": "status", "cat": "misc"},
    {"name": "Disqus", "url": "https://disqus.com/by/{}/", "check": "status", "cat": "misc"},
    {"name": "Etsy", "url": "https://www.etsy.com/shop/{}", "check": "status", "cat": "misc"},
    {"name": "Fiverr", "url": "https://www.fiverr.com/{}", "check": "status", "cat": "misc"},
    {"name": "Ebay", "url": "https://www.ebay.com/usr/{}", "check": "status", "reliable": False, "cat": "misc"},
    {"name": "Cash App", "url": "https://cash.app/${}", "check": "status",
     "reliable": False, "cat": "misc"},
]
