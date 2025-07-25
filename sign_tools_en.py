import os
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# -------- Configuration --------
signatureBeginTag = "SIGNATURE-BEGIN"
signatureEndTag = "SIGNATURE-END"

# Supported extensions and their corresponding comment styles (prefix, suffix)
commentStyles = {
    '.py':   ('# ', '#'),
    '.sh':   ('# ', '#'),
    '.c':    ('// ', '//'),
    '.h':    ('// ', '//'),
    '.cpp':  ('// ', '//'),
    '.go':   ('// ', '//'),
    '.js':   ('// ', '//'),
    '.html': ('<!-- ', ' -->'),
    '.xml':  ('<!-- ', ' -->'),
}

defaultCommentStyle = ('# ', '#')  # Default comment style

# -------- Helper Functions --------

def getCommentStyle(fileExtension):
    """Return the comment prefix and suffix based on file extension, default to '#' comments."""
    return commentStyles.get(fileExtension.lower(), defaultCommentStyle)

def removeSignatureBlock(textContent, fileExtension):
    """Remove the signature block from text to avoid duplicate signing."""
    commentPrefix, commentSuffix = getCommentStyle(fileExtension)
    beginLine = f"{commentPrefix}{signatureBeginTag}{commentSuffix}".strip()
    endLine = f"{commentPrefix}{signatureEndTag}{commentSuffix}".strip()

    textLines = textContent.splitlines()
    filteredLines = []
    insideSignatureBlock = False

    for lineContent in textLines:
        if lineContent.strip() == beginLine:
            insideSignatureBlock = True
            continue
        if lineContent.strip() == endLine:
            insideSignatureBlock = False
            continue
        if not insideSignatureBlock:
            filteredLines.append(lineContent)

    return "\n".join(filteredLines)

def extractSignature(textContent, fileExtension):
    """Extract the Base64 signature string and the content excluding the signature block."""
    commentPrefix, commentSuffix = getCommentStyle(fileExtension)
    beginLine = f"{commentPrefix}{signatureBeginTag}{commentSuffix}".strip()
    endLine = f"{commentPrefix}{signatureEndTag}{commentSuffix}".strip()

    textLines = textContent.splitlines()
    extractedSignatureBase64 = None
    insideSignatureBlock = False
    contentLines = []

    for lineContent in textLines:
        strippedLine = lineContent.strip()
        if strippedLine == beginLine:
            insideSignatureBlock = True
            continue
        if strippedLine == endLine:
            insideSignatureBlock = False
            continue

        if insideSignatureBlock:
            sigLine = strippedLine
            if sigLine.startswith(commentPrefix):
                sigLine = sigLine[len(commentPrefix):]
            if sigLine.endswith(commentSuffix):
                sigLine = sigLine[:-len(commentSuffix)]
            extractedSignatureBase64 = sigLine.strip()
        else:
            contentLines.append(lineContent)

    contentWithoutSignature = "\n".join(contentLines)
    return extractedSignatureBase64, contentWithoutSignature

# -------- Signing and Verification --------

def generateKeyPair():
    """Generate an Ed25519 key pair and save to files."""
    privateKeySavePath = input("Please enter the private key save path (e.g., private.key): ").strip()
    publicKeySavePath = input("Please enter the public key save path (e.g., public.key): ").strip()

    privateKeyInstance = Ed25519PrivateKey.generate()
    privateKeyBytes = privateKeyInstance.private_bytes(
        encoding=1,             # Encoding.Raw = 1
        format=1,               # PrivateFormat.Raw = 1
        encryption_algorithm=0  # NoEncryption = 0
    )
    publicKeyInstance = privateKeyInstance.public_key()
    publicKeyBytes = publicKeyInstance.public_bytes(
        encoding=1,             # Encoding.Raw = 1
        format=1                # PublicFormat.Raw = 1
    )

    try:
        with open(privateKeySavePath, 'wb') as privateKeyFile:
            privateKeyFile.write(privateKeyBytes)
        with open(publicKeySavePath, 'wb') as publicKeyFile:
            publicKeyFile.write(publicKeyBytes)
    except Exception as exceptionError:
        print(f"Failed to save key files: {exceptionError}")
        return

    print(f"✅ Key pair generated successfully. Private key: {privateKeySavePath}, Public key: {publicKeySavePath}")

def signFile(privateKeyInstance, filePath):
    """Sign a single file and append the signature block."""
    if not os.path.isfile(filePath):
        print(f"File not found: {filePath}")
        return

    fileRoot, fileExtension = os.path.splitext(filePath)
    commentPrefix, commentSuffix = getCommentStyle(fileExtension)

    try:
        with open(filePath, 'r', encoding='utf-8') as targetFile:
            originalTextContent = targetFile.read()
    except Exception as exceptionError:
        print(f"Failed to read the file: {exceptionError}")
        return

    # Remove existing signature block if present
    contentWithoutSignature = removeSignatureBlock(originalTextContent, fileExtension)
    contentBytes = contentWithoutSignature.encode('utf-8')

    try:
        signatureBytes = privateKeyInstance.sign(contentBytes)
        signatureBase64String = base64.b64encode(signatureBytes).decode('ascii')
    except Exception as exceptionError:
        print(f"Signing failed: {exceptionError}")
        return

    signatureBlockLines = [
        f"{commentPrefix}{signatureBeginTag}{commentSuffix}",
        f"{commentPrefix}{signatureBase64String}{commentSuffix}",
        f"{commentPrefix}{signatureEndTag}{commentSuffix}"
    ]
    signatureBlock = "\n".join(signatureBlockLines)

    if not contentWithoutSignature.endswith('\n'):
        contentWithoutSignature += '\n'
    newFileContent = contentWithoutSignature + signatureBlock + '\n'

    try:
        with open(filePath, 'w', encoding='utf-8') as targetFile:
            targetFile.write(newFileContent)
    except Exception as exceptionError:
        print(f"Failed to write to file: {exceptionError}")
        return

    print(f"✅ Successfully signed file: {filePath}")

def verifyFile(publicKeyInstance, filePath):
    """Verify the signature of a single file."""
    if not os.path.isfile(filePath):
        print(f"File not found: {filePath}")
        return

    fileRoot, fileExtension = os.path.splitext(filePath)

    try:
        with open(filePath, 'r', encoding='utf-8') as targetFile:
            fileTextContent = targetFile.read()
    except Exception as exceptionError:
        print(f"Failed to read the file: {exceptionError}")
        return

    signatureBase64String, contentWithoutSignature = extractSignature(fileTextContent, fileExtension)

    if signatureBase64String is None:
        print(f"⚠️ File is not signed: {filePath}")
        return

    try:
        signatureBytes = base64.b64decode(signatureBase64String)
    except Exception as exceptionError:
        print(f"Signature format error: {exceptionError}")
        return

    try:
        publicKeyInstance.verify(signatureBytes, contentWithoutSignature.encode('utf-8'))
        print(f"✅ Signature verified successfully: {filePath}")
    except InvalidSignature:
        print(f"❌ Invalid signature: {filePath}")
    except Exception as exceptionError:
        print(f"Verification failed: {exceptionError}")

def signDirectory(privateKeyInstance, directoryPath, acceptedExtensions):
    """Recursively sign all files with specified extensions in directory."""
    if not os.path.isdir(directoryPath):
        print(f"Directory not found: {directoryPath}")
        return

    for directoryRoot, directoryNames, fileNames in os.walk(directoryPath):
        for currentFileName in fileNames:
            currentFileExtension = os.path.splitext(currentFileName)[1].lower()
            if currentFileExtension in acceptedExtensions:
                currentFileFullPath = os.path.join(directoryRoot, currentFileName)
                signFile(privateKeyInstance, currentFileFullPath)

def verifyDirectory(publicKeyInstance, directoryPath, acceptedExtensions):
    """Recursively verify signature of all files with specified extensions in directory."""
    if not os.path.isdir(directoryPath):
        print(f"Directory not found: {directoryPath}")
        return

    for directoryRoot, directoryNames, fileNames in os.walk(directoryPath):
        for currentFileName in fileNames:
            currentFileExtension = os.path.splitext(currentFileName)[1].lower()
            if currentFileExtension in acceptedExtensions:
                currentFileFullPath = os.path.join(directoryRoot, currentFileName)
                verifyFile(publicKeyInstance, currentFileFullPath)

# -------- Main Interaction --------

def main():
    print("Ed25519 File Signing and Verification Tool")
    print("1. Generate Key Pair")
    print("2. Sign Single File")
    print("3. Verify Single File")
    print("4. Sign Directory")
    print("5. Verify Directory")
    print("0. Exit")

    while True:
        userChoice = input("Please enter your choice (0-5): ").strip()
        if userChoice == '0':
            print("Exiting the program.")
            break
        elif userChoice == '1':
            generateKeyPair()
        elif userChoice == '2':
            privateKeyPathInput = input("Enter private key file path: ").strip()
            filePathInput = input("Enter file path to sign: ").strip()

            if not os.path.isfile(privateKeyPathInput):
                print("Private key file does not exist.")
                continue

            try:
                privateKeyDataBytes = open(privateKeyPathInput, 'rb').read()
                privateKeyInstance = Ed25519PrivateKey.from_private_bytes(privateKeyDataBytes)
            except Exception as exceptionError:
                print(f"Failed to load private key: {exceptionError}")
                continue

            signFile(privateKeyInstance, filePathInput)
        elif userChoice == '3':
            publicKeyPathInput = input("Enter public key file path: ").strip()
            filePathInput = input("Enter file path to verify: ").strip()

            if not os.path.isfile(publicKeyPathInput):
                print("Public key file does not exist.")
                continue

            try:
                publicKeyDataBytes = open(publicKeyPathInput, 'rb').read()
                publicKeyInstance = Ed25519PublicKey.from_public_bytes(publicKeyDataBytes)
            except Exception as exceptionError:
                print(f"Failed to load public key: {exceptionError}")
                continue

            verifyFile(publicKeyInstance, filePathInput)
        elif userChoice == '4':
            privateKeyPathInput = input("Enter private key file path: ").strip()
            directoryPathInput = input("Enter directory path to sign: ").strip()
            extensionsInputRaw = input("Enter file extensions to sign separated by spaces (default for multiple languages if empty): ").strip()

            if not os.path.isfile(privateKeyPathInput):
                print("Private key file does not exist.")
                continue

            try:
                privateKeyDataBytes = open(privateKeyPathInput, 'rb').read()
                privateKeyInstance = Ed25519PrivateKey.from_private_bytes(privateKeyDataBytes)
            except Exception as exceptionError:
                print(f"Failed to load private key: {exceptionError}")
                continue

            if extensionsInputRaw:
                acceptedExtensions = set(extensionsInputRaw.split())
            else:
                acceptedExtensions = set(commentStyles.keys())

            signDirectory(privateKeyInstance, directoryPathInput, acceptedExtensions)
        elif userChoice == '5':
            publicKeyPathInput = input("Enter public key file path: ").strip()
            directoryPathInput = input("Enter directory path to verify: ").strip()
            extensionsInputRaw = input("Enter file extensions to verify separated by spaces (default for multiple languages if empty): ").strip()

            if not os.path.isfile(publicKeyPathInput):
                print("Public key file does not exist.")
                continue

            try:
                publicKeyDataBytes = open(publicKeyPathInput, 'rb').read()
                publicKeyInstance = Ed25519PublicKey.from_public_bytes(publicKeyDataBytes)
            except Exception as exceptionError:
                print(f"Failed to load public key: {exceptionError}")
                continue

            if extensionsInputRaw:
                acceptedExtensions = set(extensionsInputRaw.split())
            else:
                acceptedExtensions = set(commentStyles.keys())

            verifyDirectory(publicKeyInstance, directoryPathInput, acceptedExtensions)
        else:
            print("Invalid option, please try again.")

if __name__ == "__main__":
    main()
