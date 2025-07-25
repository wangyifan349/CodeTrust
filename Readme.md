# Ed25519 File Digital Signature Tool 🔐📄

## Project Overview

This project provides a digital signing and verification tool based on the modern cryptographic algorithm Ed25519, specially designed for source code and text files. It helps developers add tamper-proof digital signatures to files, allowing anyone to quickly verify file integrity and author identity.

Signatures are appended as comments, ensuring no impact on program execution and facilitating everyday development and code hosting.

---

## Background and Motivation 🚩

Code security is increasingly important in open source and enterprise projects. The following issues frequently occur:

- ❌ **Malicious code tampering**: Attackers insert backdoors or malicious code.
- ❌ **Impersonation of developers**: Someone submits code pretending to be others, damaging reputation.
- ❌ **Smearing developers**: Modifying code to create vulnerabilities or bad behavior, harming original authors.
- ❌ **Supply chain attacks**: Exploiting source code repository vulnerabilities to implant malicious code.

These seriously threaten software security, enterprise reputation, and developer rights.

---

## Role and Principle of Digital Signatures 🔍

Digital signatures are a key cryptographic technique effectively preventing the issues above. The basic principles are:

1. **Private key signing**  
   Developers use their private key—held only by themselves—to generate a signature of the file content. The signature is an encrypted "fingerprint" uniquely tied to the content.

2. **Public key verification**  
   Anyone holding the developer's public key can verify the signature matches the file content, confirming the file is unmodified and genuinely signed by the private key holder.

3. **Data integrity assurance**  
   Any modification of file content will cause signature verification to fail, helping quickly detect tampering.

4. **Identity authentication**  
   Only the private key holder can generate the signature, preventing forgery and identity spoofing.

---

## Why Choose Ed25519? ⚡

- A modern asymmetric encryption algorithm with very strong security, offering some resistance against quantum attacks.
- Fast signing and verification, suitable for large files and batch operations.
- Short signature length (64 bytes), convenient for embedding in file comments.
- Widely supported in crypto libraries (e.g., Python's cryptography), easy to integrate.

---

## Features ✨

- 🚀 **Generate Ed25519 key pairs**: Keys saved in raw bytes format, simple and secure.
- ✍️ **Sign single files or batch directories**: Recursively supported, multiple programming language file extensions supported.
- 🔍 **Verify file signatures**: Accurately identify tampering, verify signature validity.
- 💬 **Multi-language comment support**: Automatically use corresponding comment syntax for files (e.g., `#`, `//`, `<!-- -->`), no code execution impact.
- 🛡️ **Securely embed signature info**: Signature block appended at file end, easy to view and verify without breaking code structure.

---

## Usage Example 🌟

Signature block example (Python file):

```python
# SIGNATURE-BEGIN
# MCowBQYDK2VwAyEAz0nY83u1tsU8sV9pbEdcrbqYBWeIYEQH27PEOa1KI3Iw=
# SIGNATURE-END
```

This is a Base64-encoded signature wrapped in comments, completely ignored during program execution with no effect.

---

## Important Security Tips ⚠️

- **Strictly protect your private key!** Leakage enables attackers to forge signatures and break security.
- **Public keys can be distributed openly**, allowing users to verify signature authenticity.
- It is recommended to publish signed files in trusted repositories to ensure software supply chain safety.
- Rotate keys periodically to mitigate risks from long-term usage.
- Consider publishing public key hashes or fingerprints across multiple channels for easy verification.

---

## Why Does Your Project Need This Tool? 💡

- **Protect developer rights**: Prevent impersonation or defamation.
- **Enhance code trustworthiness**: Users and auditors can instantly verify authenticity.
- **Defend against supply chain attacks**: Quickly detect malicious tampering to safeguard the software ecosystem.
- **Support multi-language environments**: Rich comment syntax support fits diverse codebases.
- **Easy process integration**: Can be integrated into CI/CD pipelines for automated signing and verification.

---

## Installation and Running 🚀

1. **Install dependencies:**

```bash
pip install cryptography
```

2. **Run the script and follow prompts:**

```bash
python sign_tool.py
```

---

## Contribution and Feedback 🙌

Contributions via issues and PRs are welcome to improve functionality and security features. We hope this project helps all developers build safer and more trustworthy code environments!

---

## License 📄

This project is licensed under the MIT License. Feel free to use and modify, but please retain the original author attribution.

---

Thank you for choosing and trusting this tool! Let's build a transparent, fair, and trustworthy software world together. ✨
