"""
batch_test.py — Run multiple URLs through the phishing detector at once.
Place this file in: phishing-site-or-not/  (same folder as main.py)
Run with: python batch_test.py
"""

import subprocess
import json
import sys
import time
from datetime import datetime

# ── TEST URLS ──────────────────────────────────────────────────────────────────
TEST_URLS = [
    "https://member17.agency-connect-profile.com/",
    "https://ynabioueconus-meriescs-experinces-t.vercel.app/",
    "https://www.ynabioueconus-meriescs-experinces-t.vercel.app/",
    "https://member427.partner-business-hub.com/",
    "https://ftx.claims-notification.com/portal-claims/?id=Y2FsY3VsYXRvYXJlcGl0ZXN0aS5jb20",
    "https://desenrolabrasil2026.site/",
    "https://www.app86365.cc/",
    "https://survey.refassured.com/mbMDN5NK",
    "http://survey.refassured.co/mbMDN5NK",
    "https://id-meta.busines-help-center.com/",
    "http://diogohenriquedotpy.github.io/meus-sites-favoritos",
    "http://finnest.ink/yago/index.html",
    "https://usa_bluckfilouin.godaddysites.com/",
    "https://hughssherika896572396.pages.dev/help/contact/521544119187011/",
    "https://loenwe-hopeagia-noprobs.pages.dev/help/contact/289022682371252",
    "http://studyioiyy.b-cdn.net/all1.html?eta=mirus2@f0fca16225d1fa713bfefd56bbd8674cead3.org",
    "https://novolimitepratodos.s3.us-east-005.backblazeb2.com/aumento.html",
    "https://www.amazon-clone-gray-psi.vercel.app/",
    "http://ipfs.io/ipfs/bafybeid77ah547l36ef5c5m7o24ooophtfyhddpm64ku5ubxi6wvdsh3oy",
    "https://sites.google.com/view/wetrsfer/accueil/",
    "https://synva-nalra-biz01-prixo-dexma-spct1.pages.dev/heartily_welcome?id=845957945277545&page_name=AryaSpa/",
    "https://croatiapools.com/DK/DKB/dkb/login.php/",
    "https://discord-clone-rajdeep019.vercel.app/login",
    "https://mattcreamer17-gif.github.io/bank-of-america/",
    "http://artmedal.ir/ggyg/alibaba/",
    "http://ipfs.io/ipfs/bafkreidykzihrphv3kincyjruk34txtfvtja5rfilg4dffcdgoic7est54",
    "https://nandaatenatec.github.io/clone-spotify/",
    "http://javi-salas-dev.github.io/duplicate-Netflix",
    "https://adiraneazkuenaga.es/cn/en.php?rand=13inboxlightaspxn.1774256418",
    "https://easy-bank-landing-page-pi.vercel.app/",
    "https://easy-bank-landing-page-ecru.vercel.app/",
    "https://shrutitomar02.github.io/Amazon-Project/checkout.html",
    "https://sab8942.github.io/Amazon-clone/",
    "https://sheetaljanghu-design.github.io/Amazon-UI/",
    "https://mhamedkbt.github.io/NetflixPrj/",
    "https://easybank-landing-page-xi-eight.vercel.app/",
    "https://update-exodus-helpcentre.vercel.app/",
    "https://my-site-103180-108737.weeblysite.com/",
    "https://clover-infotech-internal.github.io/clover-ai-chatboat-compass/",
    "https://view-help---auth---bitmert--sso.webflow.io/",
    "https://finance-ndax.pages.dev/",
    "https://www.robiox.com.ua/users/7426339782/profile?https://www.roblox.com/users/7426339782/profile=",
    "https://us-support-ledgor-en.pages.dev/page1.html/page2.html/",
    "https://mayuresh-2601.github.io/Netflix-Clone/",
    "https://namanjain-git.github.io/Netflix-UI-Clone/",
    "https://kcoinlogin.github.io/",
    "https://next-ab-clone-apetta.vercel.app/",
    "https://mandalacraft.ro/lop/admin%20verify/",
    "https://tamaratav.github.io/Netflix/",
    "https://portal-live-ledgar.webflow.io/",
    "https://ddeepakgoutam2005.github.io/Netflix_Clone/",
    "https://apple-responsive-frontend.vercel.app/",
    "https://zeynepsudeilaslan.github.io/netflix-website-bootstrap/",
    "https://www.robiox.com.ua/games/11729688377/Booga-Booga?privateServerLinkCode=92750181032122628380385966605650",
    "https://jhamilan.github.io/Netflix-Clone/",
    "https://karankumae.github.io/netflixclone/",
    "https://shruti01022004.github.io/NETFLIX-UI-clone/",
    "https://public-trezo.vercel.app/",
    "https://jjanahh274-eng.github.io/portofoliocs/",
    "https://help--ledgerlivelad.webflow.io/",
    "https://sso-blockfee.webflow.io/",
    "https://galexcarrion.github.io/steam/",
    "https://netflix-clone-qu144p5yp-lumiereproductions.vercel.app/",
    "https://abhishekkumar2280.github.io/Netflix-Clone/",
    "https://pub-1e5d76a3f07d40fca9aaa348be68acb6.r2.dev/Client:DogsForOurBraveEventDate%204:07:2026Tue.html",
    "https://edu4life.github.io/amazon-project-version-1/",
    "http://www.vlkote.hop.ru/",
    "https://us-support-ledgor-en.pages.dev/page1.html/page4.html/page2.html/",
    "https://loginservice.cloud/E.lEcQSl9-99fHIQ?/linkedin/slink?code=afSN103785",
    "https://fdgfdg.center-meta-agency.com/",
    "https://fnaver.netlify.app/nidlogin.login/?naps",
    "https://login-finan2026.gamer.gd/",
    "http://red-mud-f702.kendallelsaxbthtp0668.workers.dev/email-notification2e3waXFarD_eFq_tvhuJl8ff%3Bfr%3D1lyxrntvqTbTboazV.AWccO3ZxPz8a78gk_aXXTrSbCR2jUDllDnMyiTKvp4YMycirUlo.Bp8iie..AAA.0.0.Bp8iie.AWfdP6EKabBlBt6U0GYa0PcIPxQ",
    "https://login-pichinha.hstn.me/",
    "https://www.joyfullmint-drop7.vercel.app/",
    "https://armt.cloud/devices/0027044E39FD",
    "https://telasmaster.serveirc.com/sicred/Portal.php",
    "http://microsoftquarantine.authorised-support.com/login/review/wjy99UrJpywk6FVPPIN_vx51xfx1Jt7X1UEQ=7Bg==0XVlTQl9DX1ZEb1xfV1leb0dZRFhvQFFDQ0dfQlQ=/qVL0fNmNYahdj2smOXWXeggfE1TOi_hb/",
    "https://www.robiox.com.ps/users/6528622062/profile",
    "https://secur-servenupdates.b-cdn.net/secure.html?eta=kalospro@9940cf839c8806745bd7b4900dafd8a656e5.net/",
    "http://khushijain3103.github.io/Instagram-Love",
    "https://codebyprathmesh.github.io/Amazon_Clone/",
    "http://pub-f4bf4b5c581d4d2fae8ac6d8e8ea7310.r2.dev/woad.html",
    "https://mdkamran623.github.io/Amazon-clone/",
    "https://www.robiox.com.py/users/473677855297/profile",
    "http://member37.agency-connection-hub.com/",
    "https://princemedia.co.za/mipaz/pages/login.php",
    "https://www.robiox.com.py/users/267220066116/profile",
    "https://aumento25.s3.us-east-005.backblazeb2.com/aumento.html",
    "https://crditoecuadoenlinea.gt.tc/",
    "http://firewalll.b-cdn.net/11a.html",
    "http://profile-meta.busines-help-center.com/",
    "https://armt.cloud/devices/002704488C51",
    "https://portal-cliente.hstn.me/",
    "https://desaplicadas.vu/bgt5/others.html?eta=maror9@ab14f2274f9be61f966367b15882eba516d5.com",
    "https://agency-manager.accounts-admin-agency.com/",
    "https://agency-marketing.accounts-admin-agency.com/",
    "https://member24.agency-connection-hub.com/",
    "https://jkblog790.netlify.app/playerunknowns-battlegrounds",
    "http://jkblog790.netlify.app/playerunknowns-battlegrounds.html/",
    "http://member35.agency-connection-hub.com/",
    "https://meta-id17660.invoice-ads-manager.com/",
    "https://meta-id17659.invoice-ads-manager.com/",
    "http://thatpartllc.co/wp-admin/sf/sf_marley/sf_marley",
    "http://kidcarteer.b-cdn.net/all2.html?eta=elen@af4ca0094d3b1404f6b727ea8d84549f47f5.org",
    "http://serves-9eprotection.vercel.app/jsecsev.html?eta=renenhub@7048b0f77cf7408ea29da6189a080712327c.com",
    "http://verifasoli.webcindario.com/",
    "https://seunovolimitealtoliberado.s3.us-east-005.backblazeb2.com/aumento.html",
    "http://updatesubs-netfilx.dynv6.net/login",
    "http://updatesubs-netfilx.dynv6.net/",
    "https://kuiocnlogen.gitbook.io/",
    "https://sso-en-ca-netcoins-com-nav-azure.webflow.io/",
    "https://ribanholdlogip.gitbook.io/",
    "https://badging.it-support-group.com/s/63BZGFSVBWSFCDX7Y9/584dd8/90eab167-7429-489f-99f6-ce86e8d0d81a",
    "https://inicioinusual365.webcindario.com/",
    "https://web2.pancake.run/info/tokens/0x2170ed0880ac9a755fd29b2688956bd959f933f8",
    "https://trkloge23.serv00.net/dkb/login.php",
    "https://maida1610.github.io/Amazon-clone/",
    "https://faiyazusmani.github.io/instagram/",
    "https://vishal7398.github.io/avs/index.html",
    "http://f.digitalmaillane.com/igit/4/222vni5Mfeym7n6hxrM1t8MuxqlmwMgrwMstlM4hMxMq",
    "https://crackaf-bubbles-frontend.vercel.app/swap",
    "https://niharika0732.github.io/Project_Sem1/",
    "https://ww.viettevghy2026.kesug.com/facebook-meta-ads2026",
    "https://discontcomputers.com/2513501.doc/18a80a/fad0f483-81b2-45c6-ad47-7272058d9cb6",
    "https://zxd365756.com/index_m.html",
    "https://hems.standard.us-east-1.oortstorages.com/11.znc",
    "https://netflix-clone-azure-ten.vercel.app/",
    "https://microsoft.authorised-support.com/new-account/EOzAFbYj1bjLmgufSIlKJJR9Kpvsy5kc3UkY=3Ag==5WFxWR1pGWlNBallaUlxbakJcQV1qRVRGRkJaR1E=/6Xx5KG1mKRNjeU3rSnC8diFTM7R4V1de",
    "https://enuganduladineshkumar.github.io/Netflix-Clone-Landing-page/",
    "https://gestao.current-news-alerts.com/s/63BZGFSVBWSFCDX7Y9/584dd8/90eab167-7429-489f-99f6-ce86e8d0d81a",
    "https://gh.cyberfish.io/s/63BZGFSVBWSFCDX7Y9/584dd8/90eab167-7429-489f-99f6-ce86e8d0d81a",
    "https://fortflarefn.github.io/roblox.github.io/",
    "http://shantanu024.github.io/Netflix-Clone",
    "https://abhimanyu088.github.io/netflix-clone/",
    "http://kaarthi0312.github.io/Instagram-copy-page",
    "https://secure-web-ndxxa-cdns.typedream.app/",
    "https://netflix-clone-azure-seven.vercel.app/",
    "https://ledfgt-xmvtyoz.pages.dev/index.htm/",
    "https://rentrise.vercel.app/",
    "https://emilemoraes.github.io/Netflix-Clone-/",
    "https://shabin-hussain.github.io/facebook_login/",
    "https://inner.website/443332cc8w6a2146c65a1833ca7b1ccd1a38.html",
    "https://inner.website/x7198cf00060b941ffu8424c456q6cd00f38.html",
    "https://sgr4fa.pages.dev/-/zh/gp/video/detail/0q7g46igupnjj9zutowrmf8nst/ref=atv_pp_tt_9",
    "https://notifyhubss.net/de0e811287ec9f469epa0aa42e72111ca8fe.html",
    "https://inner.website/4c34e6ef9w4c4147d958e2603a2b61622c8e.html",
    "https://inner.website/15bcca81a100994290f90c2f3c6fa100e443.html",
    "https://www.uspsmailjourney.com/home",
    "http://xdanaidnpayltersp.teocix.my.id/",
    "http://f.digitalmaillane.com/igit/4/5t2frilU1qu1lizaqkU3b1Ue36xwkU0vpUlmeUxaUqUj",
    "http://f.digitalmaillane.com/igit/4/bigkqjpFj1n8c9q1hbFu2sFrg6xukFrmgFed5Fo1FhFa",
    "https://radhachavan.github.io/My_website/",
    "https://956882coinbase.com/",
    "https://humanresources-team.com/s/63BZGFSVBWSFCDX7Y9/584dd8/90eab167-7429-489f-99f6-ce86e8d0d81a",
    "https://phiscientificholdings.com/2513501.doc/18a80a/fad0f483-81b2-45c6-ad47-7272058d9cb6",
    "https://ledger.updatesetup.com/",
    "https://whatsapp-clone-peach-nine.vercel.app/login",
    "https://webfun.website/landingpages/a462b1ba-cbb5-4aec-853c-99f6af486dd1/jhAEYEtInnqYxzPh_N4lL-B6doAiM3LckFuEP39p2Kc",
    "https://central.pr-universe.com/s/63BZGFSVBWSFCDX7Y9/584dd8/90eab167-7429-489f-99f6-ce86e8d0d81a/",
    "https://sahanajambagi.github.io/amazon_clone/",
    "http://mail.supplier-gas-elpiji.duckdns.org/",
    "https://tax.securebankinggroup.com/s/63BZGFSVBWSFCDX7Y9/584dd8/90eab167-7429-489f-99f6-ce86e8d0d81a",
    "https://allhrgroup.com/s/63BZGFSVBWSFCDX7Y9/584dd8/90eab167-7429-489f-99f6-ce86e8d0d81a/",
    "https://ms-en.github.io/lnstagram/",
    "https://chinkotemple.github.io/monfigs/",
    "https://airbnb-alpha-coral.vercel.app/",
    "https://contact-account-client.com/",
    "https://biswarup96.github.io/cloneofnetflix/",
    "https://dkcode1706.github.io/netflix-clone/",
    "http://facebook-member.bussines-partner-agency.com/",
    "http://f.digitalmaillane.com/igit/4/9aqqgz3Ynu95em5gwqYlx7Ygco6q0YktvYuskY3gYwYp",
    "https://rohanmore20.github.io/Project-Netflix-Clone/",
    "https://banban87.github.io/banana/",
    "https://dhlsupplychaintest.earcu.com/jobs/login",
    "https://site-6aa3879fh.godaddysites.com/",
    "https://meta-id17658.invoice-ads-manager.com/",
    "https://inner.website/jc7dfe04275484474069e879b267b917cacb.html",
    "https://accounts.bmwweb.systems/en/login",
    "https://sso--netcoins-com--cdn-oauth.webflow.io/",
    "https://theblueheart321-max.github.io/Amazon-clone/",
    "https://sarthak312004.github.io/Netflix_cln/",
    "https://ecount-update.vercel.app/",
    "https://yashaitt.github.io/Netflix-clone/netflix-signup.html",
    "http://aktifkanpayylater.ijj.my.id/",
    "https://instagram-clone-kappa-five.vercel.app/",
    "https://kucoinrewards.blogspot.com/",
    "http://trilova.com.br/wp-includes/images/smilies/?ai=Gsolex@661f473f1606f68678eada72ac26d980b864.com",
    "https://home-rent-application.vercel.app/",
    "https://dnaxx-ld.nxtxle.biz.id/x/int.html",
    "https://anusriyacp.github.io/amazon-clone/",
    "https://shreyajaiswal0808.github.io/PROJECT-main/",
    "https://lmoriw-iekascma-oqmmcq-213-cmakwe-fgacsax.pages.dev/help/contact/422625022731437",
    "https://nr7571808-bit.github.io/Amazon-clone/",
    "https://ubercar-site.web.app/",
    "https://joaogallindo-dev.github.io/Clone-Netflix/",
    "https://netflix-clone-red-seven.vercel.app/",
    "https://netflix-clone-tan-six.vercel.app/",
    "https://imarsalan-tech.github.io/amazon-website/",
    "https://spotify.servernotification.events/premium/campaign/rejoin6m/login/jYIzT3IkJkRzitEx5knZyYGJ069Fh6em0RVs=6Bw==9SklWTVBfQGZVVl5QVw==/PFbnBhvz5dwOkHR1eD_R-l48VOHQKA2m/",
    "https://semdesculpaparasuassolucoes.s3.us-east-005.backblazeb2.com/aumento.html",
    "https://pqsolutions.org/yak/rogers/",
    "https://pqsolutions.org/yak/rogers",
    "http://www.mexcdefi.com/h5/",
    "https://applelocalizar.com/KvnLR/",
    "https://member11.agency-ad-meta.com/",
    "https://comtamsabichuongsiungonn.pages.dev/help/contact/633659756476066",
    "http://u6u.site/",
    "https://dpd.zplmqxjtrv.cfd/com",
    "https://survey.refassured.com/BeWnoLnm",
    "http://arunvbiradar.github.io/instagram-clone",
    "http://adsmaxtt.putunesimbah.de/",
    "http://register27.agency-partner-management.com/",
    "https://aumentosolicitadomaio.s3.us-east-005.backblazeb2.com/aumento.html",
    "https://bridge-home--trezor.gitbook.io/us",
    "http://bridge-home--trezor.gitbook.io/",
    "https://maiorlimiteagora.s3.us-east-005.backblazeb2.com/aumento.html",
    "https://agency-network.accounts-admin-agency.com/",
    "https://www.16ue-casefb751962.vercel.app/",
    "https://agency-service.accounts-admin-agency.com/",
    "https://pqsolutions.org/yak/rogers/login.html",
    "https://www.free-instagram-followers-mocha.vercel.app/",
    "https://free-instagram-followers-mocha.vercel.app/",
    "http://www.nethubcorp.com/a57dc89e5gafef46a46bc0d58a4d0b6cf305.html",
    "https://asistenciahoy.com/?r=9f5adc1a-07a7-4de3-b3cb-e368f57c684b&rg=eu",
    "https://ericasantiago.com.br/0utFix/Mr_Khan/",
    "https://ericasantiago.com.br/0utFix/Mr_Khan/index2.php",
    "http://01bced66.sweet-credit-9cdf.pages.dev/",
    "https://net1.vercel.app/",
    "https://banque-online.com/?r=ad85ef05-2f84-483c-9666-7f58616606bd&rg=eu",
    "http://luiplky.b-cdn.net/all1.html",
    "https://partner-sync.credit-agency-meta.com/",
    "https://husnainjavaid856.github.io/netflix-ui-clone/",
    "https://sherkar.github.io/Amazon_Web_Clone/",
    "https://members-meta.accounts-admin-agency.com/",
    "http://web-git-05-08-trystagingbutprobwillfailbcunauthe-c7b77b-uniswap.vercel.app/portfolio",
    "http://web-git-05-08-trystagingbutprobwillfailbcunauthe-c7b77b-uniswap.vercel.app/swap",
    "https://auth-io-ttrezrcdn.gitbook.io/us",
    "http://auth-io-ttrezrcdn.gitbook.io/",
    "https://aumento75.s3.us-east-005.backblazeb2.com/aumento.html",
    "https://auth-metasmskchrrm.gitbook.io/us",
    "http://auth-metasmskchrrm.gitbook.io/",
    "https://automation-meta.accounts-admin-agency.com/",
    "https://hotel-stay77213.com/1006451789",
    "https://kuckoinlogen.gitbook.io/us",
    "http://kuckoinlogen.gitbook.io/",
    "https://member-sync.credit-agency-meta.com/",
    "https://jsz.nyx.temporary.site/3https.netflix.com.pago.php/",
    "https://caseid0030.marketing-network.agency/",
    "https://kixcoinlognin.gitbook.io/us",
    "http://kixcoinlognin.gitbook.io/",
    "https://agency-partner.accounts-admin-agency.com/",
]

# ── CONFIG ─────────────────────────────────────────────────────────────────────
PYTHON_BIN  = "python"   # change to "py" if on Windows and python doesn't work
MAIN_PATH   = "main.py"
TIMEOUT_SEC = 60

# ── RISK LEVEL DISPLAY ─────────────────────────────────────────────────────────
RISK_ICONS = {
    "CRITICAL": "🚨",
    "HIGH":     "⚠️ ",
    "MODERATE": "🟡",
    "LOW":      "✅",
}

# ── RUNNER ─────────────────────────────────────────────────────────────────────
def run_url(url: str) -> dict:
    try:
        result = subprocess.run(
            [PYTHON_BIN, MAIN_PATH, url],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SEC,
        )
        raw = result.stdout.strip()
        if not raw:
            return {"url": url, "error": "No output", "stderr": result.stderr[:200]}
        return json.loads(raw)
    except subprocess.TimeoutExpired:
        return {"url": url, "error": f"Timed out after {TIMEOUT_SEC}s"}
    except json.JSONDecodeError as e:
        return {"url": url, "error": f"Bad JSON: {e}", "raw": result.stdout[:300]}
    except Exception as e:
        return {"url": url, "error": str(e)}


# ── DISPLAY ────────────────────────────────────────────────────────────────────
def display(index: int, total: int, result: dict):
    url       = result.get("url", "?")
    short_url = url[:70] + "..." if len(url) > 70 else url

    if "error" in result:
        print(f"  [{index}/{total}] ❌ ERROR — {short_url}")
        print(f"         {result['error']}")
        return

    if "message" in result:
        print(f"  [{index}/{total}] 🔍 {short_url}")
        print(f"         → {result['message']}")
        return

    risk    = result.get("risk_level", "?")
    score   = result.get("scores", {}).get("final_weighted_score", 0)
    pred    = result.get("prediction", "?").upper()
    ml_prob = result.get("ml_probability", 0)
    icon    = RISK_ICONS.get(risk, "❓")
    classif = result.get("classification", "")
    flags   = result.get("flags", {})

    print(f"  [{index}/{total}] {icon} {risk:8s} ({score:5.1f}%)  —  {short_url}")
    print(f"         ML: {pred} ({ml_prob:.2f})  |  {classif}")

    active_flags = []
    if flags.get("free_hosting"):    active_flags.append("free_hosting")
    if flags.get("ip_url"):          active_flags.append("ip_url")
    if not flags.get("ssl_valid"):   active_flags.append("no_ssl")
    if flags.get("unreachable"):     active_flags.append("unreachable")
    if flags.get("typosquat_target"):
        active_flags.append(
            f"typosquat→{flags['typosquat_target']}({flags.get('typosquat_score', 0):.2f})"
        )
    if active_flags:
        print(f"         Flags: {', '.join(active_flags)}")


# ── SUMMARY ────────────────────────────────────────────────────────────────────
def summary(results: list):
    counts      = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0, "OTHER": 0}
    no_site     = 0
    error_count = 0

    for r in results:
        if "error" in r:
            error_count += 1
        elif "message" in r:
            no_site += 1
        else:
            level = r.get("risk_level", "OTHER")
            counts[level if level in counts else "OTHER"] += 1

    tested   = len(results) - error_count
    detected = counts["CRITICAL"] + counts["HIGH"]

    print("\n" + "═" * 65)
    print(f"  FINAL SUMMARY  ({datetime.now().strftime('%H:%M:%S')})")
    print("═" * 65)
    print(f"  Total URLs submitted : {len(results)}")
    print(f"  Successfully tested  : {tested}")
    print(f"  🚨 CRITICAL          : {counts['CRITICAL']}")
    print(f"  ⚠️  HIGH              : {counts['HIGH']}")
    print(f"  🟡 MODERATE          : {counts['MODERATE']}")
    print(f"  ✅ LOW               : {counts['LOW']}")
    print(f"  🔍 No such site      : {no_site}")
    print(f"  ❌ Errors            : {error_count}")
    print("─" * 65)
    detection_rate = (detected / tested * 100) if tested > 0 else 0
    print(f"  Flagged HIGH+CRITICAL: {detected}/{tested}  ({detection_rate:.1f}%)")
    print("═" * 65)


# ── MAIN ───────────────────────────────────────────────────────────────────────
def main():
    total = len(TEST_URLS)
    print("═" * 65)
    print(f"  PHISHING BATCH TEST — {total} URLs")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Est. time: {total * 30 // 60}–{total * 45 // 60} minutes")
    print("═" * 65 + "\n")

    results = []
    for i, url in enumerate(TEST_URLS, 1):
        print(f"  Testing [{i}/{total}] {url[:65]}...")
        sys.stdout.flush()
        start   = time.time()
        result  = run_url(url)
        elapsed = time.time() - start
        results.append(result)
        display(i, total, result)
        print(f"         Time: {elapsed:.1f}s\n")

    summary(results)

    out_file = f"batch_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Full results saved to: {out_file}\n")


if __name__ == "__main__":
    main()