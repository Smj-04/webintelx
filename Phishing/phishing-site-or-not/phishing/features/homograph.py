import unicodedata

def homograph_check(domain):
    try:
        domain.encode("ascii")
        return 0  # normal domain
    except:
        return 1  # suspicious unicode characters
