# Contributing

Contributions are welcome.

## Development Setup

```bash
git clone https://github.com/YOUR-USERNAME/cyber-storage-verifier.git
cd cyber-storage-verifier
python -m venv .venv
.venv\Scripts\activate
python cyber_storage_verifier.py
```

## Contribution Guidelines

- Keep the app safe: do not add raw disk write functionality.
- Preserve existing scan/report features unless the change is clearly documented.
- Test on Windows before submitting UI or storage-detection changes.
- Avoid adding heavy dependencies unless necessary.
- Include screenshots for UI changes when possible.
