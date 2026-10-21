
import os
import io
import json
import zipfile
import hashlib
import re
from pathlib import Path
from datetime import datetime, timezone

import boto3
import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
from botocore.exceptions import BotoCoreError, ClientError


# ==================================================
# CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="Cryptora Cloud",
    page_icon="☁️",
    layout="wide",
)

BASE_DIR = Path(__file__).parent
KEY_FILE = BASE_DIR / "secret.key"

BUCKET_NAME = "secure-cloud-bhakti-2026-demo"
AWS_REGION = "ap-southeast-2"
S3_PREFIX = "cryptora-encrypted/"
BLOCK_SIZE = 1024


# ==================================================
# ENCRYPTION KEY
# ==================================================

def get_fernet():
    """Load the existing key from AWS environment, Streamlit Secrets, or local file."""

    key = os.environ.get("FERNET_KEY")

    if not key:
        try:
            key = st.secrets.get("FERNET_KEY")
        except Exception:
            key = None

    if not key and KEY_FILE.exists():
        key = KEY_FILE.read_bytes().strip()

    if not key:
        raise RuntimeError(
            "Encryption key is not configured. Configure FERNET_KEY "
            "in AWS or keep your original secret.key locally."
        )

    if isinstance(key, str):
        key = key.encode("utf-8")

    return Fernet(key)


# ==================================================
# AMAZON S3
# ==================================================

def get_s3_client():
    """Use AWS credentials from environment or the normal AWS credential chain."""

    kwargs = {"region_name": AWS_REGION}

    access_key = os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    session_token = os.environ.get("AWS_SESSION_TOKEN")

    if access_key and secret_key:
        kwargs["aws_access_key_id"] = access_key
        kwargs["aws_secret_access_key"] = secret_key

        if session_token:
            kwargs["aws_session_token"] = session_token

    return boto3.client("s3", **kwargs)


# ==================================================
# FILE HELPERS
# ==================================================

def safe_filename(filename):
    name = Path(filename).name
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name)
    return name or "uploaded_file"


def calculate_sha256(data):
    return hashlib.sha256(data).hexdigest()


# ==================================================
# ENCRYPTION AND PACKAGING
# ==================================================

def encrypt_file(original_data, original_filename):
    cipher = get_fernet()
    original_filename = safe_filename(original_filename)

    encrypted_blocks = []

    for start in range(0, len(original_data), BLOCK_SIZE):
        chunk = original_data[start:start + BLOCK_SIZE]
        encrypted_blocks.append(cipher.encrypt(chunk))

    manifest = {
        "format": "cryptora-v1",
        "original_filename": original_filename,
        "original_size": len(original_data),
        "block_size": BLOCK_SIZE,
        "block_count": len(encrypted_blocks),
        "sha256": calculate_sha256(original_data),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    output = io.BytesIO()

    with zipfile.ZipFile(
        output,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        archive.writestr(
            "manifest.json",
            json.dumps(manifest, indent=2),
        )

        for index, block in enumerate(encrypted_blocks, start=1):
            archive.writestr(
                f"blocks/block_{index:05d}.enc",
                block,
            )

    return output.getvalue(), manifest


# ==================================================
# DECRYPTION AND RESTORATION
# ==================================================

def decrypt_file(encrypted_zip):
    cipher = get_fernet()

    try:
        with zipfile.ZipFile(io.BytesIO(encrypted_zip), "r") as archive:
            names = archive.namelist()

            if "manifest.json" not in names:
                raise ValueError("Cryptora manifest not found.")

            manifest = json.loads(archive.read("manifest.json"))

            if manifest.get("format") != "cryptora-v1":
                raise ValueError(
                    "This is not a cryptora-v1 package. "
                    "Your older packages may need your previous app version."
                )

            block_count = int(manifest["block_count"])

            if block_count < 0 or block_count > 100000:
                raise ValueError("Invalid block count.")

            restored = bytearray()

            for index in range(1, block_count + 1):
                block_name = f"blocks/block_{index:05d}.enc"

                if block_name not in names:
                    raise ValueError(f"Missing block: {block_name}")

                restored.extend(
                    cipher.decrypt(archive.read(block_name))
                )

            original_data = bytes(restored)

            if len(original_data) != int(manifest["original_size"]):
                raise ValueError("Restored file size does not match.")

            if calculate_sha256(original_data) != manifest["sha256"]:
                raise ValueError("SHA-256 integrity verification failed.")

            return original_data, manifest

    except InvalidToken:
        raise ValueError(
            "Decryption failed. Check that the original encryption key is configured."
        )
    except (zipfile.BadZipFile, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ValueError(f"Invalid encrypted package: {error}") from error


# ==================================================
# S3 UPLOAD / LIST / DOWNLOAD
# ==================================================

def upload_to_s3(encrypted_data, original_filename):
    s3 = get_s3_client()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    filename = safe_filename(original_filename)
    object_key = f"{S3_PREFIX}{timestamp}_{filename}.cryptora.zip"

    s3.put_object(
        Bucket=BUCKET_NAME,
        Key=object_key,
        Body=encrypted_data,
        ContentType="application/zip",
        Metadata={
            "application": "cryptora-cloud",
            "encryption": "fernet",
        },
    )

    return object_key


def list_s3_files():
    s3 = get_s3_client()
    files = []

    paginator = s3.get_paginator("list_objects_v2")

    for page in paginator.paginate(
        Bucket=BUCKET_NAME,
        Prefix=S3_PREFIX,
    ):
        for item in page.get("Contents", []):
            files.append(item)

    return sorted(
        files,
        key=lambda item: item["LastModified"],
        reverse=True,
    )


def download_from_s3(object_key):
    s3 = get_s3_client()

    response = s3.get_object(
        Bucket=BUCKET_NAME,
        Key=object_key,
    )

    return response["Body"].read()


# ==================================================
# FRONTEND STYLING
# ==================================================

st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #0b1220, #14213d);
    color: #f8fafc;
}
.main-title {
    font-size: 42px;
    font-weight: 800;
    color: #dbeafe;
}
.subtitle {
    color: #a5b4cc;
    font-size: 16px;
    margin-bottom: 22px;
}
div.stButton > button {
    border-radius: 10px;
    min-height: 42px;
    font-weight: 600;
}
</style>
""", unsafe_allow_html=True)


# ==================================================
# SIDEBAR
# ==================================================

with st.sidebar:
    st.markdown("## ☁️ Cryptora Cloud")
    st.caption("Secure cloud file storage")
    st.divider()

    st.write("🔐 Fernet encryption")
    st.write("🧩 1 KB blocks")
    st.write("☁️ Amazon S3 storage")
    st.write("🛡️ SHA-256 verification")

    st.divider()
    st.caption("AWS Region")
    st.code(AWS_REGION)
    st.caption("S3 prefix")
    st.code(S3_PREFIX)


# ==================================================
# MAIN HEADER
# ==================================================

st.markdown(
    '<div class="main-title">☁️ Cryptora Cloud</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="subtitle">'
    'Encrypt locally in the application. Store encrypted packages in Amazon S3.'
    '</div>',
    unsafe_allow_html=True,
)

st.info(
    "Files are encrypted by this Python application before their encrypted "
    "packages are uploaded to S3."
)

upload_tab, download_tab, security_tab = st.tabs(
    ["⬆️ Upload & Encrypt", "⬇️ Download & Decrypt", "🔒 Security"]
)


# ==================================================
# UPLOAD TAB
# ==================================================

with upload_tab:
    st.subheader("Upload and encrypt")

    uploaded_file = st.file_uploader(
        "Choose a file",
        key="cryptora_file_upload",
    )

    if uploaded_file is not None:
        original_data = uploaded_file.getvalue()

        col1, col2, col3 = st.columns(3)

        col1.metric("File name", uploaded_file.name)
        col2.metric("File size", f"{len(original_data):,} bytes")
        col3.metric(
            "Blocks",
            (len(original_data) + BLOCK_SIZE - 1) // BLOCK_SIZE,
        )

        st.caption("SHA-256 of original file")
        st.code(calculate_sha256(original_data))

        if st.button(
            "🔐 Encrypt & Upload to S3",
            type="primary",
            use_container_width=True,
        ):
            try:
                with st.spinner("Encrypting and uploading..."):
                    encrypted_zip, manifest = encrypt_file(
                        original_data,
                        uploaded_file.name,
                    )

                    object_key = upload_to_s3(
                        encrypted_zip,
                        uploaded_file.name,
                    )

                st.success("Encrypted package uploaded to Amazon S3!")

                col1, col2 = st.columns(2)
                col1.metric("Encrypted blocks", manifest["block_count"])
                col2.metric("Package size", f"{len(encrypted_zip):,} bytes")

                st.write("**S3 object key**")
                st.code(object_key)

                st.download_button(
                    "⬇️ Download encrypted ZIP",
                    data=encrypted_zip,
                    file_name=f"{safe_filename(uploaded_file.name)}.cryptora.zip",
                    mime="application/zip",
                    use_container_width=True,
                )

            except Exception as error:
                st.error(f"Upload failed: {error}")


# ==================================================
# DOWNLOAD TAB
# ==================================================

with download_tab:
    st.subheader("Download and restore")

    if st.button("🔄 Refresh S3 file list", use_container_width=True):
        st.session_state["cryptora_refresh"] = (
            st.session_state.get("cryptora_refresh", 0) + 1
        )

    try:
        files = list_s3_files()

        if not files:
            st.warning("No encrypted packages found in the configured S3 prefix.")
        else:
            labels = {
                (
                    f"{item['Key']} | {item['Size']:,} bytes | "
                    f"{item['LastModified'].strftime('%Y-%m-%d %H:%M UTC')}"
                ): item["Key"]
                for item in files
            }

            selected_label = st.selectbox(
                "Select an encrypted package",
                list(labels.keys()),
            )

            selected_key = labels[selected_label]

            action = st.radio(
                "Choose operation",
                [
                    "Download encrypted package",
                    "Decrypt and restore original",
                ],
                horizontal=True,
            )

            if st.button(
                "⬇️ Download from S3",
                type="primary",
                use_container_width=True,
            ):
                with st.spinner("Retrieving package from S3..."):
                    encrypted_zip = download_from_s3(selected_key)

                st.success("Package downloaded from S3.")

                if action == "Download encrypted package":
                    st.download_button(
                        "Save encrypted ZIP",
                        data=encrypted_zip,
                        file_name=Path(selected_key).name,
                        mime="application/zip",
                        use_container_width=True,
                    )

                else:
                    restored_data, manifest = decrypt_file(encrypted_zip)

                    st.success(
                        "Decryption successful. SHA-256 verification passed."
                    )

                    st.write("**Verified SHA-256**")
                    st.code(calculate_sha256(restored_data))

                    st.download_button(
                        "⬇️ Save restored original file",
                        data=restored_data,
                        file_name=safe_filename(
                            manifest["original_filename"]
                        ),
                        mime="application/octet-stream",
                        use_container_width=True,
                    )

    except Exception as error:
        st.error(f"S3 or download operation failed: {error}")


# ==================================================
# SECURITY TAB
# ==================================================

with security_tab:
    st.subheader("How Cryptora Cloud works")

    st.markdown("""
    1. Select a file.
    2. The application encrypts the file in 1 KB blocks using Fernet.
    3. Encrypted blocks and a manifest are packaged into a ZIP.
    4. The encrypted package is uploaded to Amazon S3.
    5. The package can be downloaded and decrypted with the original key.
    6. SHA-256 verifies that the restored content matches the original.
    """)

    st.warning(
        "Never publish your encryption key or AWS credentials. "
        "The public website needs appropriate access controls before "
        "being used for confidential files."
    )


# ==================================================
# FOOTER
# ==================================================

st.divider()

st.caption(
    "Cryptora Cloud | Python | Fernet | Amazon S3"
)
