# Artifact storage

All generated build outputs must go directly to Cloudflare R2. Follow ARTIFACT-STORAGE.md and use scripts/r2-artifacts.mjs. Keep GitHub source and release metadata free of installers, archives, trained models, generated screenshots and license bundles. Preserve private storage for keystores and customer/license data. Never reintroduce GitHub artifact actions, binary release attachments or committed generated review branches. Preserve existing product publisher tests and release-promotion gates.
