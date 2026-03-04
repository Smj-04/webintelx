# features/domain_features.py

def extract_domain_features(row):
    """
    Extract domain-related features from a dataset row.
    """

    features = {}

    # Existing domain features (safe access using .get)
    features["DomainLength"] = row.get("DomainLength", 0)
    features["IsDomainIP"] = row.get("IsDomainIP", 0)
    features["TLDLength"] = row.get("TLDLength", 0)
    features["TLDLegitimateProb"] = row.get("TLDLegitimateProb", 0)
    features["URLSimilarityIndex"] = row.get("URLSimilarityIndex", 0)
    features["CharContinuationRate"] = row.get("CharContinuationRate", 0)
    features["URLCharProb"] = row.get("URLCharProb", 0)
    features["NoOfSubDomain"] = row.get("NoOfSubDomain", 0)

    # ✅ NEW FEATURE: Brand Similarity
    features["BrandSimilarity"] = row.get("BrandSimilarity", 0)

    return features
