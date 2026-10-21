
import streamlit as st
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from botocore.exceptions import BotoCoreError, ClientError
import boto3
import hashlib
import io
import json
import zipfile
import re
from datetime import datetime, timezone


# ==================================================
# CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="Cryptora Cloud",
    page_icon="☁️",
    layout="wide",
    initial_sidebar_state="expanded",
)

BASE_DIR = Path(__file__).parent
KEY_FILE = BASE_DIR / "secret.key"

BUCKET_NAME = "secure-cloud-bhakti-2026-demo"
AWS_REGION = "ap-southeast-2"
S3_PREFIX = "cryptora-encrypted/"
BLOCK_SIZE = 1024


# ==================================================
# SECURITY KEY
# ==================================================

def get_fernet():
    """Read the existing encryption key from Streamlit Secrets or local file."""
    key = None

    try:
        key = st.secrets.get("FERNET_KEY")
    except Exception:
        pass

    if key:
        if isinstance(key, str):
            key = key.encode("utf-8")
        return Fernet(key)

    if KEY_FILE.exists():
        return Fernet(KEY_FILE.read_bytes().strip())

    raise RuntimeError(
        "Encryption key not found. Add your original secret.key "
        "locally or configure FERNET_KEY in Streamlit Secrets."
    )


# ==================================================
# AWS S3 CONNECTION
# ==================================================

def get_s3_client():
    """Use Streamlit Secrets in deployment or normal AWS credentials locally."""
    try:
        try:
            access_key = st.secrets.get("AWS_ACCESS_KEY_ID")
            secret_key = st.secrets.get("AWS_SECRET_ACCESS_KEY")
            session_token = st.secrets.get("AWS_SESSION_TOKEN")
        except Exception:
            access_key = None
            secret_key = None
            session_token = None

        if access_key and secret_key:
            kwargs = {
                "region_name": AWS_REGION,
                "aws_access_key_id": access_key,
                "aws_secret_access_key": secret_key,
            }
            if session_token:
                kwargs["aws_session_token"] = session_token

            return boto3.client("s3", **kwargs)

        return boto3.client("s3", region_name=AWS_REGION)

    except Exception as error:
        raise RuntimeError(f"Could not initialize AWS S3: {error}") from error


# ==================================================
# FILE HELPERS
# ==================================================

def calculate_sha256(data):
    return hashlib.sha256(data).hexdigest()


def safe_filename(filename):
    """Remove path components and unsafe filename characters."""
    name = Path(filename).name
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name)
    return name or "uploaded_file"


def encrypt_file(original_data, original_filename):
    """Encrypt the file in blocks and package the encrypted blocks and manifest."""
    cipher = get_fernet()
    original_filename = safe_filename(original_filename)

    blocks = []
    for start in range(0, len(original_data), BLOCK_SIZE):
        chunk = original_data[start:start + BLOCK_SIZE]
        blocks.append(cipher.encrypt(chunk))

    # Represent an empty file with zero encrypted blocks.
    manifest = {
        "format": "cryptora-v1",
        "original_filename": original_filename,
        "original_size": len(original_data),
        "block_size": BLOCK_SIZE,
        "block_count": len(blocks),
        "sha256": calculate_sha256(original_data),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    package = io.BytesIO()

    with zipfile.ZipFile(
        package, "w", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        archive.writestr(
            "manifest.json",
            json.dumps(manifest, indent=2),
        )

        for index, encrypted_block in enumerate(blocks, start=1):
            archive.writestr(
                f"blocks/block_{index:05d}.enc",
                encrypted_block,
            )

    return package.getvalue(), manifest


def decrypt_file(encrypted_zip):
    """Restore the original file from a Cryptora encrypted ZIP."""
    cipher = get_fernet()

    try:
        with zipfile.ZipFile(io.BytesIO(encrypted_zip), "r") as archive:
            names = archive.namelist()

            if "manifest.json" not in names:
                raise ValueError("The ZIP has no Cryptora manifest.")

            manifest = json.loads(archive.read("manifest.json"))

            if manifest.get("format") != "cryptora-v1":
                raise ValueError(
                    "This ZIP uses a different or older format. "
                    "Keep your backup app.py and use the matching "
                    "decryption code for this package."
                )

            block_count = int(manifest["block_count"])
            if block_count < 0 or block_count > 1_000_000:
                raise ValueError("Invalid encrypted block count.")

            restored = bytearray()

            for index in range(1, block_count + 1):
                block_name = f"blocks/block_{index:05d}.enc"

                if block_name not in names:
                    raise ValueError(f"Missing encrypted block: {block_name}")

                encrypted_block = archive.read(block_name)
                restored.extend(cipher.decrypt(encrypted_block))

            original_data = bytes(restored)

            if len(original_data) != int(manifest["original_size"]):
                raise ValueError("Restored file size does not match.")

            actual_hash = calculate_sha256(original_data)
            expected_hash = manifest["sha256"]

            if actual_hash != expected_hash:
                raise ValueError("SHA-256 verification failed.")

            return original_data, manifest

    except (zipfile.BadZipFile, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ValueError(f"Invalid or damaged Cryptora package: {error}") from error


# ==================================================
# S3 OPERATIONS
# ==================================================

def upload_to_s3(encrypted_data, original_filename):
    s3 = get_s3_client()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    clean_name = safe_filename(original_filename)

    object_key = (
        f"{S3_PREFIX}{timestamp}_{clean_name}.cryptora.zip"
    )

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
            files.append({
                "key": item["Key"],
                "size": item["Size"],
                "modified": item["LastModified"],
            })

    return sorted(
        files,
        key=lambda item: item["modified"],
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
# FRONTEND DESIGN
# ==================================================

st.markdown("""
<style>
    .stApp {
        background: linear-gradient(140deg, #0b1220 0%, #111c32 100%);
        color: #f8fafc;
    }
    .main-title {
        font-size: 42px;
        font-weight: 800;
        letter-spacing: -1px;
        color: #e0f2fe;
        margin-bottom: 0;
    }
    .subtitle {
        color: #a8b7cc;
        font-size: 16px;
        margin-top: 6px;
        margin-bottom: 22px;
    }
    .info-card {
        background: rgba(30, 41, 59, 0.8);
        border: 1px solid #334155;
        border-radius: 15px;
        padding: 18px;
        margin-bottom: 12px;
    }
    .small-label {
        color: #9caec5;
        font-size: 13px;
    }
    div.stButton > button {
        border-radius: 10px;
        font-weight: 650;
        min-height: 42px;
    }
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## ☁️ Cryptora Cloud")
    st.caption("Secure file storage")
    st.divider()

    st.markdown("### Security")
    st.write("🔐 Fernet encryption")
    st.write("🧩 1 KB encrypted blocks")
    st.write("☁️ Amazon S3 storage")
    st.write("🛡️ SHA-256 integrity check")

    st.divider()
    st.caption("AWS Region")
    st.code(AWS_REGION)
    st.caption("S3 storage prefix")
    st.code(S3_PREFIX)

st.markdown(
    '<div class="main-title">☁️ Cryptora Cloud</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="subtitle">Encrypt locally. Store securely. Restore when needed.</div>',
    unsafe_allow_html=True,
)

st.info(
    "Your file is encrypted by this Python application before the encrypted "
    "package is uploaded to Amazon S3."
)

upload_tab, download_tab, about_tab = st.tabs(
    ["⬆️ Upload & Encrypt", "⬇️ Download & Decrypt", "🔒 About Security"]
)


# ==================================================
# UPLOAD TAB
# ==================================================

with upload_tab:
    st.subheader("Upload and encrypt a file")
    st.write(
        "Choose a file. Cryptora encrypts it in blocks and stores the "
        "encrypted ZIP package in your configured S3 bucket."
    )

    uploaded_file = st.file_uploader(
        "Choose a file to secure",
        key="cryptora_upload",
    )

    if uploaded_file is not None:
        original_data = uploaded_file.getvalue()

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("File name", uploaded_file.name)

        with col2:
            st.metric("Original size", f"{len(original_data):,} bytes")

        with col3:
            st.metric(
                "Encryption blocks",
                max(1, (len(original_data) + BLOCK_SIZE - 1) // BLOCK_SIZE)
                if original_data else 0,
            )

        st.caption(
            "Original SHA-256: "
            + calculate_sha256(original_data)
        )

        if st.button(
            "🔐 Encrypt & Upload to S3",
            type="primary",
            use_container_width=True,
        ):
            try:
                with st.spinner("Encrypting file and uploading to Amazon S3..."):
                    encrypted_zip, manifest = encrypt_file(
                        original_data,
                        uploaded_file.name,
                    )

                    object_key = upload_to_s3(
                        encrypted_zip,
                        uploaded_file.name,
                    )

                st.success("Encrypted package uploaded successfully!")

                st.markdown("### Upload receipt")

                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Encrypted blocks", manifest["block_count"])
                with col2:
                    st.metric("Encrypted package", f"{len(encrypted_zip):,} bytes")

                st.write("**S3 object key**")
                st.code(object_key)

                st.write("**Original SHA-256**")
                st.code(manifest["sha256"])

                st.download_button(
                    "⬇️ Download encrypted ZIP",
                    data=encrypted_zip,
                    file_name=f"{safe_filename(uploaded_file.name)}.cryptora.zip",
                    mime="application/zip",
                    use_container_width=True,
                )

                st.caption(
                    "The receipt confirms the upload request succeeded. "
                    "You can verify the object independently in the AWS S3 console."
                )

            except (RuntimeError, ValueError, BotoCoreError, ClientError) as error:
                st.error(f"Upload failed: {error}")
            except Exception as error:
                st.error(f"Unexpected error: {error}")


# ==================================================
# DOWNLOAD TAB
# ==================================================

with download_tab:
    st.subheader("Retrieve your encrypted files")
    st.write(
        "List encrypted packages in S3, download one, and optionally restore "
        "the original file."
    )

    if st.button("🔄 Refresh S3 file list", use_container_width=True):
        st.session_state["cryptora_refresh"] = (
            st.session_state.get("cryptora_refresh", 0) + 1
        )

    try:
        files = list_s3_files()

        if not files:
            st.warning(
                "No objects were found under the configured S3 prefix. "
                "Upload a file first and verify the bucket and prefix."
            )
        else:
            options = {
                (
                    f"{item['key']} | {item['size']:,} bytes | "
                    f"{item['modified'].strftime('%Y-%m-%d %H:%M UTC')}"
                ): item["key"]
                for item in files
            }

            selected_label = st.selectbox(
                "Choose an encrypted package",
                list(options.keys()),
            )
            selected_key = options[selected_label]

            action = st.radio(
                "Choose an operation",
                ["Download encrypted package", "Decrypt and restore original"],
                horizontal=True,
            )

            if st.button(
                "⬇️ Download from S3",
                type="primary",
                use_container_width=True,
            ):
                with st.spinner("Downloading package from S3..."):
                    encrypted_zip = download_from_s3(selected_key)

                st.success("Encrypted package downloaded from S3.")

                if action == "Download encrypted package":
                    st.download_button(
                        "Save encrypted package",
                        data=encrypted_zip,
                        file_name=Path(selected_key).name,
                        mime="application/zip",
                        use_container_width=True,
                    )

                else:
                    try:
                        with st.spinner("Decrypting and verifying the file..."):
                            restored_data, manifest = decrypt_file(encrypted_zip)

                        original_filename = safe_filename(
                            manifest["original_filename"]
                        )

                        st.success(
                            "File decrypted successfully. SHA-256 verification passed."
                        )

                        col1, col2 = st.columns(2)

                        with col1:
                            st.metric(
                                "Restored file size",
                                f"{len(restored_data):,} bytes",
                            )

                        with col2:
                            st.metric(
                                "Encrypted blocks",
                                manifest["block_count"],
                            )

                        st.write("**Verified SHA-256**")
                        st.code(calculate_sha256(restored_data))

                        st.download_button(
                            "⬇️ Save restored original file",
                            data=restored_data,
                            file_name=original_filename,
                            mime="application/octet-stream",
                            use_container_width=True,
                        )

                    except (InvalidToken, ValueError, KeyError, TypeError) as error:
                        st.error(f"Decryption or verification failed: {error}")

    except (RuntimeError, BotoCoreError, ClientError) as error:
        st.error(f"Could not access Amazon S3: {error}")
        st.info(
            "Check the AWS credentials, bucket name, region, and IAM permissions."
        )
    except Exception as error:
        st.error(f"Unexpected error while loading S3 files: {error}")


# ==================================================
# SECURITY TAB
# ==================================================

with about_tab:
    st.subheader("How Cryptora Cloud works")

    st.markdown("""
    **1. Select a file**  
    The user chooses a file from their device.

    **2. Encrypt the file**  
    The application divides the file into 1 KB blocks and encrypts each block
    using Fernet symmetric encryption.

    **3. Store in Amazon S3**  
    The encrypted blocks and a manifest are packaged into a ZIP file.
    The encrypted package is uploaded to the configured S3 bucket.

    **4. Retrieve and decrypt**  
    The application downloads the package, decrypts each block, and reconstructs
    the original file.

    **5. Verify integrity**  
    SHA-256 is calculated again and compared with the original hash recorded
    in the manifest.
    """)

    st.warning(
        "Keep your encryption key private and backed up. Anyone who obtains "
        "the key and encrypted package may be able to recover the original file."
    )

    st.caption(
        "The public website URL does not itself provide user authentication "
        "or access control. Configure AWS IAM permissions and application "
        "access controls appropriately before storing sensitive data."
    )


# ==================================================
# FOOTER
# ==================================================

st.divider()

st.markdown(
    "<div style='text-align:center;color:#94a3b8;'>"
    "Cryptora Cloud · Python · Fernet · Amazon S3"
    "</div>",
    unsafe_allow_html=True,
)

