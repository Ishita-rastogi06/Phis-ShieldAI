# Legacy UCI 30-feature schema

The bundled `url_lexical_detector.joblib` remains a historical UCI-feature
artifact. It is optional telemetry, never the platform verdict and never a
requirement for URL enrichment.

The following historical fields cannot be collected faithfully for arbitrary
global URLs and are intentionally never fabricated: `web_traffic`,
`Page_Rank`, `Google_Index`, `Links_pointing_to_page`, and
`Statistical_report`. Consequently the legacy artifact reports unavailable
telemetry unless a future, versioned retraining process replaces the schema.

The canonical platform verdict instead aggregates independent evidence from
local URL/DNS/TLS/website/WHOIS inspection, brand detection, VirusTotal,
urlscan, URLhaus and OpenPhish. A provider no-match or failure is never a
safe result.
