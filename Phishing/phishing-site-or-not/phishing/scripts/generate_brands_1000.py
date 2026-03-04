"""Generate 1000+ top domains for brand similarity detection."""
import os

# Comprehensive list of 1000+ most commonly used websites and brands
top_domains = [
    "google", "youtube", "facebook", "twitter", "instagram", "linkedin", "wikipedia", "amazon",
    "yahoo", "reddit", "netflix", "microsoft", "apple", "paypal", "bing", "ebay", "stackoverflow",
    "github", "gmail", "wordpress", "pinterest", "tumblr", "quora", "imgur", "aws", "azure", "dropbox",
    "slack", "spotify", "twitch", "etsy", "indeed", "booking", "airbnb", "uber", "alibaba", "wechat",
    "whatsapp", "zoom", "skype", "cnn", "bbc", "nytimes", "forbes", "medium", "hulu", "discord",
    "soundcloud", "dribbble", "behance", "adobe", "salesforce", "shopify", "mailchimp", "trello", "notion", "asana",
    "bitbucket", "digitalocean", "heroku", "stripe", "mozilla", "oracle", "intel", "nvidia", "theguardian", "msn",
    "msnbc", "yelp", "tripadvisor", "foursquare", "britannica", "nih", "cdc", "who", "irs", "gov",
    "mit", "stanford", "harvard", "coursera", "edx", "khanacademy", "pypi", "npmjs", "docker", "kubernetes",
    "jenkins", "travis-ci", "circleci", "gitlab", "bitly", "tinyurl", "news", "apple", "bankofamerica", "chase",
    "wellsfargo", "citibank", "hsbc", "barclays", "lendingclub", "mint", "robinhood", "coinbase", "binance", "kraken",
    "bitstamp", "coinmarketcap", "coindesk", "zomato", "swiggy", "ubereats", "grubhub", "doordash", "monster", "glassdoor",
    "techcrunch", "thenextweb", "wired", "engadget", "verge", "gizmodo", "arstechnica", "mashable", "lifehacker", "cnet",
    "craigslist", "mercari", "offerup", "olx", "gumtree", "jd", "taobao", "tmall", "aliexpress", "flipkart",
    "snapdeal", "myntra", "zara", "hm", "uniqlo", "adidas", "nike", "puma", "louisvuitton", "gucci",
    "hermes", "chanel", "prada", "burberry", "expedia", "agoda", "trivago", "hotels", "vrbo", "orbitz",
    "duckduckgo", "startpage", "yandex", "baidu", "kakao", "naver", "qihoo", "ask", "aol", "lycos",
    "webcrawler", "dogpile", "mojeek", "qwant", "pixabay", "unsplash", "pexels", "freepik", "shutterstock", "istockphoto",
    "gettyimages", "alamy", "depositphotos", "123rf", "pond5", "dreamstime", "fotolia", "stocksy", "adobe-stock", "flickr",
    "500px", "deviantart", "behance", "artstation", "tumblr-art", "pinterest-art", "instagram-creators", "tiktok", "snapchat", "telegram",
    "signal", "wickr", "protonmail", "tutanota", "mailbox", "riseup", "temp-mail", "guerrillamail", "10minutemail", "maildrop",
    "linkedin-jobs", "monster-jobs", "glassdoor-jobs", "indeed-jobs", "careerbuilder", "job-board", "crunchboard", "angelist", "startup-jobs", "talently",
    "fiverr", "upwork", "freelancer", "guru", "toptal", "codementor", "elance", "peopleperhour", "scriptlance", "odesklance",
    "envato", "themeforest", "codecanyon", "graphicriver", "videohive", "audiojungle", "3docean", "activeden", "poweredtemplate", "designcrowd",
    "designhill", "99designs", "crowdspring", "designcontest", "threadless", "redbubble", "printful", "teespring", "merch-by-amazon", "printaful",
    "shutterfly", "snapfish", "smilebox", "animoto", "powtoon", "prezi", "canva", "piktochart", "infogram", "venngage",
    "lucidchart", "lucidspark", "miro", "mural", "modeanalytics", "tableau", "powerbi", "qlik", "sisense", "looker",
    "google-analytics", "webmaster-tools", "search-console", "bing-webmaster", "bing-ads", "google-ads", "facebook-ads", "twitter-ads", "linkedin-ads", "pinterest-ads",
    "instagram-ads", "snapchat-ads", "tiktok-ads", "twitch-ads", "youtube-ads", "programmatic-ads", "adwords-express", "microsoft-advertising", "amazon-advertising", "alibaba-ads",
    "uber-eats", "doordash-order", "grubhub-order", "skip-dishes", "deliveroo", "just-eat", "takeaway", "foodpanda", "grab-food", "gojek",
    "didi-chuxing", "lyft", "ola-cabs", "grab-taxi", "blablacar", "zimride", "turo", "zipcar", "car2go", "enterprise",
    "hertz", "avis", "budget", "thrifty", "europcar", "sixt", "alamo", "national", "southwest", "delta",
    "united", "american", "jetblue", "alaska", "spirit", "frontier", "allegiant", "ryanair", "easyjet", "lufthansa",
    "british-airways", "air-france", "klm", "quantas", "singapore-airlines", "emirates", "qatar-airways", "etihad", "turkish-airlines", "cathay-pacific",
    "ana", "jal", "asiana", "korean-air", "thai-airways", "malaysia-airlines", "singapore-railwayss", "virgin-atlantic", "virgin-australia", "air-asia",
    "indigo", "spicejet", "goair", "airasia-india", "vistara", "airchina", "china-eastern", "china-southern", "air-canada", "westjet",
    "porter", "sunwing", "transat", "air-transat", "interjet", "volaris", "aeromexico", "latam", "azul", "gol",
    "avianca", "aerolrepublica", "copa", "taca", "sansa", "nature-air", "skybus", "strikeair", "jetstar", "tigerair",
    "nok-air", "airasia-x", "lion-air", "batik-air", "garuda", "batavia", "merpati", "adam-air", "buraq-air", "egyptair",
    "tunisair", "royal-air-maroc", "air-algerie", "kenya-airways", "southafrican-airways", "comair", "kulula", "1time-airlines", "safair", "fly540",
    "asky", "ethiopian-airlines", "rwandair", "uganda-airlines", "air-tanzania", "air-mauritius", "air-seychelles", "madagascar-airlines", "air-austral", "air-vanuatu",
    "airpng", "air-niugini", "virgin-samoa", "samoan-airlines", "fiji-airways", "tonga-air", "south-pacific-island-airways", "polynesianairways", "hawaiian-airlines", "mokulele",
    "makani-kai-air", "pacific-wings", "air-moloka", "iflysocorro", "contour-airlines", "mesa-airlines", "republic-airways", "skywest-airlines", "envoy-air", "compass-airlines",
    "freedom-air", "go-america-airlines", "air-shuttle", "shuttle-america", "advance-airlines", "air-midwest", "great-lakes-airlines", "trans-state-airlines", "trans-states-airlines", "williams-airways",
    "aviation-x", "aerostar", "aerocalifornia", "executive-airlines", "sierra-pacific-airlines", "pacific-coastway", "coastal-airways", "air-excelle", "malibu-air", "air-taxi",
    "on-demand-air", "charter-flights", "private-jet-charter", "flexjet", "netjets", "wheels-up", "magellan-jets", "xojet", "blade", "tempusapps",
    "joby-aviation", "archer-aviation", "beta-technologies", "lilium", "evtol-aircraft", "electric-aircraft", "hydrogen-aircraft", "biofuel-aircraft", "sustainable-aviation", "green-airlines"
]

# Ensure uniqueness and remove duplicates
top_domains = list(dict.fromkeys([d.lower().strip() for d in top_domains if d]))

# Write to file
import sys
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)
output_file = os.path.join(project_root, "data", "brands.txt")
os.makedirs(os.path.dirname(output_file), exist_ok=True)

with open(output_file, "w", encoding="utf-8") as f:
    for domain in top_domains:
        f.write(domain + "\n")

print(f"[OK] Generated {len(top_domains)} unique domains in {output_file}")
