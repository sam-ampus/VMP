# Synthetic connector samples

Hand-written to mirror the structure of real Qualys "Scan Results" XML and Nessus `.nessus` v2
exports. **No real data:** IPs are documentation ranges (RFC 5737), hostnames are
`example.com`, and titles, outputs and QIDs/plugin ids are illustrative.

The real samples the team provided are client data and are never committed
(`sample-data-nessus-qualys/` is git-ignored). `test_real_samples.py` runs against them
when the folder is present and is skipped otherwise.
