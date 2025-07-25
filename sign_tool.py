import os
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# -------- 配置 --------
SIGN_BEGIN = "SIGNATURE-BEGIN"
SIGN_END = "SIGNATURE-END"

# 支持的扩展名及对应注释格式（前缀，后缀）
COMMENT_STYLES = {
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

DEFAULT_COMMENT = ('# ', '#')  # 默认注释格式

# -------- 辅助函数 --------

def get_comment_style(file_ext):
    """根据文件扩展名返回对应的注释前后缀，默认使用 #注释"""
    return COMMENT_STYLES.get(file_ext.lower(), DEFAULT_COMMENT)

def remove_signature_block(text, file_ext):
    """去掉文本中的签名块，避免重复签名"""
    prefix, suffix = get_comment_style(file_ext)
    sign_begin_line = f"{prefix}{SIGN_BEGIN}{suffix}".strip()
    sign_end_line = f"{prefix}{SIGN_END}{suffix}".strip()

    lines = text.splitlines()
    new_lines = []
    inside_block = False

    for line in lines:
        if line.strip() == sign_begin_line:
            inside_block = True
            continue
        if line.strip() == sign_end_line:
            inside_block = False
            continue
        if not inside_block:
            new_lines.append(line)

    return "\n".join(new_lines)

def extract_signature(text, file_ext):
    """从文本中提取签名和内容，返回（签名base64字符串，内容字符串）"""
    prefix, suffix = get_comment_style(file_ext)
    sign_begin_line = f"{prefix}{SIGN_BEGIN}{suffix}".strip()
    sign_end_line = f"{prefix}{SIGN_END}{suffix}".strip()

    lines = text.splitlines()
    signature_b64 = None
    inside_block = False
    content_lines = []

    for line in lines:
        line_strip = line.strip()
        if line_strip == sign_begin_line:
            inside_block = True
            continue
        if line_strip == sign_end_line:
            inside_block = False
            continue

        if inside_block:
            sig_line = line_strip
            if sig_line.startswith(prefix):
                sig_line = sig_line[len(prefix):]
            if sig_line.endswith(suffix):
                sig_line = sig_line[:-len(suffix)]
            signature_b64 = sig_line.strip()
        else:
            content_lines.append(line)

    content = "\n".join(content_lines)
    return signature_b64, content

# -------- 签名与验证 --------

def generate_keypair():
    """生成 Ed25519 密钥对，保存为文件"""
    priv_path = input("请输入私钥保存路径（如 private.key）：").strip()
    pub_path = input("请输入公钥保存路径（如 public.key）：").strip()

    privkey = Ed25519PrivateKey.generate()
    priv_bytes = privkey.private_bytes(
        encoding = 1,    # Encoding.Raw = 1
        format = 1,      # PrivateFormat.Raw = 1
        encryption_algorithm = 0 # NoEncryption = 0
    )
    pubkey = privkey.public_key()
    pub_bytes = pubkey.public_bytes(
        encoding = 1,    # Encoding.Raw = 1
        format = 1       # PublicFormat.Raw = 1
    )

    try:
        with open(priv_path, 'wb') as f:
            f.write(priv_bytes)
        with open(pub_path, 'wb') as f:
            f.write(pub_bytes)
    except Exception as e:
        print(f"保存密钥文件失败: {e}")
        return

    print(f"✅ 密钥对生成成功，私钥: {priv_path}，公钥: {pub_path}")

def sign_file(private_key, file_path):
    """对单个文件进行签名，并写入签名块"""
    if not os.path.isfile(file_path):
        print(f"文件不存在: {file_path}")
        return

    _, ext = os.path.splitext(file_path)
    prefix, suffix = get_comment_style(ext)

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            text = f.read()
    except Exception as e:
        print(f"读取文件失败: {e}")
        return

    # 去掉已有签名
    content_clean = remove_signature_block(text, ext)
    content_bytes = content_clean.encode('utf-8')

    # 签名
    try:
        signature = private_key.sign(content_bytes)
        signature_b64 = base64.b64encode(signature).decode('ascii')
    except Exception as e:
        print(f"签名失败: {e}")
        return

    # 构造签名块
    sign_block = "\n".join([
        f"{prefix}{SIGN_BEGIN}{suffix}",
        f"{prefix}{signature_b64}{suffix}",
        f"{prefix}{SIGN_END}{suffix}",
    ])

    # 写回文件，保留原内容去除旧签名，追加新签名块
    if not content_clean.endswith('\n'):
        content_clean += '\n'
    new_text = content_clean + sign_block + '\n'

    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_text)
    except Exception as e:
        print(f"写入文件失败: {e}")
        return

    print(f"✅ 文件签名成功: {file_path}")

def verify_file(public_key, file_path):
    """验证文件签名"""
    if not os.path.isfile(file_path):
        print(f"文件不存在: {file_path}")
        return

    _, ext = os.path.splitext(file_path)

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            text = f.read()
    except Exception as e:
        print(f"读取文件失败: {e}")
        return

    signature_b64, content = extract_signature(text, ext)

    if signature_b64 is None:
        print(f"⚠ 文件未签名: {file_path}")
        return

    try:
        signature = base64.b64decode(signature_b64)
    except Exception as e:
        print(f"签名格式错误: {e}")
        return

    try:
        public_key.verify(signature, content.encode('utf-8'))
        print(f"✅ 签名验证成功: {file_path}")
    except InvalidSignature:
        print(f"❌ 签名无效: {file_path}")
    except Exception as e:
        print(f"验证失败: {e}")

def sign_directory(private_key, dir_path, exts):
    """递归签名目录内指定后缀的所有文件"""
    if not os.path.isdir(dir_path):
        print(f"目录不存在: {dir_path}")
        return

    for root, _, files in os.walk(dir_path):
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in exts:
                full_path = os.path.join(root, filename)
                sign_file(private_key, full_path)

def verify_directory(public_key, dir_path, exts):
    """递归验证目录内指定后缀的所有文件签名"""
    if not os.path.isdir(dir_path):
        print(f"目录不存在: {dir_path}")
        return

    for root, _, files in os.walk(dir_path):
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in exts:
                full_path = os.path.join(root, filename)
                verify_file(public_key, full_path)

# -------- 主交互 --------

def main():
    print("Ed25519文件签名/验证工具")
    print("1. 生成密钥对")
    print("2. 单文件签名")
    print("3. 单文件验证")
    print("4. 批量目录签名")
    print("5. 批量目录验证")
    print("0. 退出")

    while True:
        choice = input("请输入操作编号（0-5）：").strip()
        if choice == '0':
            print("退出程序")
            break

        if choice == '1':
            generate_keypair()

        elif choice == '2':
            key_path = input("请输入私钥文件路径：").strip()
            file_path = input("请输入待签名文件路径：").strip()

            if not os.path.isfile(key_path):
                print("私钥文件不存在")
                continue

            try:
                privkey_data = open(key_path, 'rb').read()
                privkey = Ed25519PrivateKey.from_private_bytes(privkey_data)
            except Exception as e:
                print(f"加载私钥失败: {e}")
                continue

            sign_file(privkey, file_path)

        elif choice == '3':
            key_path = input("请输入公钥文件路径：").strip()
            file_path = input("请输入待验证文件路径：").strip()

            if not os.path.isfile(key_path):
                print("公钥文件不存在")
                continue

            try:
                pubkey_data = open(key_path, 'rb').read()
                pubkey = Ed25519PublicKey.from_public_bytes(pubkey_data)
            except Exception as e:
                print(f"加载公钥失败: {e}")
                continue

            verify_file(pubkey, file_path)

        elif choice == '4':
            key_path = input("请输入私钥文件路径：").strip()
            dir_path = input("请输入待签名目录路径：").strip()
            ext_str = input("请输入待签名文件后缀（空格分隔，不指定默认多种语言后缀）：").strip()

            if not os.path.isfile(key_path):
                print("私钥文件不存在")
                continue

            try:
                privkey_data = open(key_path, 'rb').read()
                privkey = Ed25519PrivateKey.from_private_bytes(privkey_data)
            except Exception as e:
                print(f"加载私钥失败: {e}")
                continue

            exts = set(ext_str.split()) if ext_str else set(COMMENT_STYLES.keys())

            sign_directory(privkey, dir_path, exts)

        elif choice == '5':
            key_path = input("请输入公钥文件路径：").strip()
            dir_path = input("请输入待验证目录路径：").strip()
            ext_str = input("请输入待验证文件后缀（空格分隔，不指定默认多种语言后缀）：").strip()

            if not os.path.isfile(key_path):
                print("公钥文件不存在")
                continue

            try:
                pubkey_data = open(key_path, 'rb').read()
                pubkey = Ed25519PublicKey.from_public_bytes(pubkey_data)
            except Exception as e:
                print(f"加载公钥失败: {e}")
                continue

            exts = set(ext_str.split()) if ext_str else set(COMMENT_STYLES.keys())

            verify_directory(pubkey, dir_path, exts)

        else:
            print("无效选项，请重新输入")

if __name__ == "__main__":
    main()
