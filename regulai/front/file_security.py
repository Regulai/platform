"""
File Upload Security Module

This module provides comprehensive security validation for file uploads.
It includes:
- Magic number validation (file signature verification)
- File size limits
- Content type validation
- Malicious file detection
- Sanitization utilities
"""

import io
import hashlib
import mimetypes
from typing import Tuple, Optional, Dict
from django.core.exceptions import ValidationError
from PIL import Image


# File type signatures (magic numbers)
FILE_SIGNATURES = {
    # Images
    'image/png': [b'\x89PNG\r\n\x1a\n'],
    'image/jpeg': [b'\xff\xd8\xff'],
    'image/gif': [b'GIF87a', b'GIF89a'],
    'image/webp': [b'RIFF', b'WEBP'],
    'image/bmp': [b'BM'],

    # Documents
    'application/pdf': [b'%PDF-'],
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': [
        b'PK\x03\x04'  # DOCX is a ZIP file
    ],
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': [
        b'PK\x03\x04'  # XLSX is a ZIP file
    ],

    # Text
    'text/plain': [],  # No specific signature for plain text
}

# Maximum file sizes (in bytes)
MAX_FILE_SIZES = {
    'image/png': 5 * 1024 * 1024,      # 5MB for images
    'image/jpeg': 5 * 1024 * 1024,     # 5MB
    'image/gif': 2 * 1024 * 1024,      # 2MB
    'image/webp': 5 * 1024 * 1024,     # 5MB
    'application/pdf': 10 * 1024 * 1024,  # 10MB for PDFs
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 10 * 1024 * 1024,  # 10MB
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 10 * 1024 * 1024,  # 10MB
    'text/plain': 1 * 1024 * 1024,     # 1MB for text
    'default': 5 * 1024 * 1024,        # 5MB default
}

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    'image': ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'],
    'document': ['pdf', 'docx', 'xlsx', 'txt'],
    'all': ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'pdf', 'docx', 'xlsx', 'txt']
}

# Dangerous extensions that should never be allowed
DANGEROUS_EXTENSIONS = [
    'exe', 'dll', 'so', 'dylib',  # Executables
    'sh', 'bat', 'cmd', 'ps1',     # Scripts
    'app', 'deb', 'rpm',           # Packages
    'jar', 'war',                  # Java
    'apk', 'ipa',                  # Mobile apps
    'scr', 'cpl', 'com',           # Windows
    'vbs', 'js', 'jse',            # Scripts
    'html', 'htm', 'svg',          # Can contain scripts
    'php', 'py', 'rb', 'pl',       # Server-side scripts
]


def get_file_extension(filename: str) -> str:
    """
    Safely extract file extension.

    Args:
        filename: The filename to extract extension from

    Returns:
        Lowercase extension without dot, or empty string if no extension
    """
    if not filename or '.' not in filename:
        return ''
    return filename.rsplit('.', 1)[1].lower()


def validate_file_extension(filename: str, allowed_types: str = 'all') -> None:
    """
    Validate file extension against whitelist.

    Args:
        filename: The filename to validate
        allowed_types: Type category ('image', 'document', 'all')

    Raises:
        ValidationError: If extension is not allowed or is dangerous
    """
    extension = get_file_extension(filename)

    if not extension:
        raise ValidationError("File must have an extension")

    # Check for dangerous extensions
    if extension in DANGEROUS_EXTENSIONS:
        raise ValidationError(
            f"File type '.{extension}' is not allowed for security reasons"
        )

    # Check against whitelist
    allowed = ALLOWED_EXTENSIONS.get(allowed_types, ALLOWED_EXTENSIONS['all'])
    if extension not in allowed:
        raise ValidationError(
            f"File type '.{extension}' is not allowed. "
            f"Allowed types: {', '.join(allowed)}"
        )


def detect_mime_type(file_content: bytes, filename: str) -> str:
    """
    Detect MIME type by checking file signature (magic numbers).
    This is more secure than relying on file extension alone.

    Args:
        file_content: The file content as bytes
        filename: The filename (used as fallback)

    Returns:
        Detected MIME type
    """
    # Check magic numbers first
    for mime_type, signatures in FILE_SIGNATURES.items():
        for signature in signatures:
            if file_content.startswith(signature):
                return mime_type

    # Special handling for WEBP (needs to check both RIFF and WEBP)
    if file_content.startswith(b'RIFF') and b'WEBP' in file_content[:20]:
        return 'image/webp'

    # Fallback to extension-based detection
    guessed_type, _ = mimetypes.guess_type(filename)
    return guessed_type or 'application/octet-stream'


def validate_file_signature(file_content: bytes, expected_mime_type: str) -> None:
    """
    Validate that file content matches expected MIME type.
    Prevents attackers from renaming malicious files.

    Args:
        file_content: The file content as bytes
        expected_mime_type: Expected MIME type based on extension

    Raises:
        ValidationError: If file signature doesn't match expected type
    """
    detected_mime = detect_mime_type(file_content, '')

    # For Office documents (ZIP-based), we can't distinguish between them by signature alone
    office_types = [
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ]

    if expected_mime_type in office_types and detected_mime in office_types:
        return  # Accept any Office document if expecting one

    # Allow plain text without signature
    if expected_mime_type == 'text/plain':
        return

    if detected_mime != expected_mime_type and detected_mime != 'application/octet-stream':
        raise ValidationError(
            f"File content doesn't match extension. "
            f"Expected {expected_mime_type}, detected {detected_mime}"
        )


def validate_file_size(file_size: int, mime_type: str) -> None:
    """
    Validate file size is within allowed limits.

    Args:
        file_size: Size of file in bytes
        mime_type: MIME type of the file

    Raises:
        ValidationError: If file exceeds size limit
    """
    max_size = MAX_FILE_SIZES.get(mime_type, MAX_FILE_SIZES['default'])

    if file_size > max_size:
        max_size_mb = max_size / (1024 * 1024)
        raise ValidationError(
            f"File size ({file_size / (1024 * 1024):.2f}MB) exceeds "
            f"maximum allowed size ({max_size_mb:.1f}MB)"
        )


def validate_image_content(file_content: bytes) -> None:
    """
    Validate image content using PIL to ensure it's a valid image.
    This helps detect corrupted or malicious images.

    Args:
        file_content: The image file content as bytes

    Raises:
        ValidationError: If image is invalid or contains suspicious content
    """
    try:
        img = Image.open(io.BytesIO(file_content))
        img.verify()  # Verify it's a valid image

        # Additional security checks
        # Check for unreasonably large dimensions (potential DoS)
        max_dimension = 10000  # 10000 pixels
        if img.width > max_dimension or img.height > max_dimension:
            raise ValidationError(
                f"Image dimensions ({img.width}x{img.height}) exceed "
                f"maximum allowed ({max_dimension}x{max_dimension})"
            )

        # Check for decompression bomb (very high pixel count with small file size)
        max_pixels = 100_000_000  # 100 megapixels
        if img.width * img.height > max_pixels:
            raise ValidationError(
                "Image has too many pixels (possible decompression bomb attack)"
            )

    except Image.DecompressionBombError:
        raise ValidationError("Image file is potentially malicious (decompression bomb)")
    except Exception as e:
        raise ValidationError(f"Invalid or corrupted image file: {str(e)}")


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal and other attacks.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename safe for storage
    """
    import re
    import unicodedata

    # Remove path components
    filename = filename.split('/')[-1].split('\\')[-1]

    # Normalize unicode characters
    filename = unicodedata.normalize('NFKD', filename)

    # Remove non-ASCII characters
    filename = filename.encode('ascii', 'ignore').decode('ascii')

    # Remove dangerous characters, keep only alphanumeric, dash, underscore, and dot
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)

    # Prevent double extensions
    filename = re.sub(r'\.+', '.', filename)

    # Limit filename length
    name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
    if len(name) > 100:
        name = name[:100]
    filename = f"{name}.{ext}" if ext else name

    return filename


def calculate_file_hashes(file_content: bytes) -> Dict[str, str]:
    """
    Calculate multiple hash values for file integrity verification.

    Args:
        file_content: File content as bytes

    Returns:
        Dictionary with hash algorithms as keys and hex digests as values
    """
    return {
        'md5': hashlib.md5(file_content).hexdigest(),
        'sha1': hashlib.sha1(file_content).hexdigest(),
        'sha256': hashlib.sha256(file_content).hexdigest(),
    }


def validate_uploaded_file(
    uploaded_file,
    allowed_types: str = 'all',
    require_image: bool = False
) -> Tuple[bytes, Dict[str, any]]:
    """
    Comprehensive validation of uploaded file.

    This is the main function to use for file upload validation.
    It performs all security checks and returns validated file content.

    Args:
        uploaded_file: Django UploadedFile object
        allowed_types: Type category ('image', 'document', 'all')
        require_image: If True, additional image validation is performed

    Returns:
        Tuple of (file_content, metadata_dict)

    Raises:
        ValidationError: If any validation check fails
    """
    # Get file info
    filename = uploaded_file.name
    file_size = uploaded_file.size

    # Step 1: Validate extension
    validate_file_extension(filename, allowed_types)
    extension = get_file_extension(filename)

    # Step 2: Read file content
    file_content = uploaded_file.read()

    # Step 3: Detect actual MIME type from content
    detected_mime = detect_mime_type(file_content, filename)

    # Step 4: Validate file signature matches extension
    expected_mime = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    validate_file_signature(file_content, expected_mime)

    # Step 5: Validate file size
    validate_file_size(file_size, detected_mime)

    # Step 6: Additional validation for images
    is_image = detected_mime.startswith('image/')
    if require_image and not is_image:
        raise ValidationError("File must be an image")

    if is_image:
        validate_image_content(file_content)

    # Step 7: Calculate hashes for integrity
    file_hashes = calculate_file_hashes(file_content)

    # Step 8: Sanitize filename
    safe_filename = sanitize_filename(filename)

    # Prepare metadata
    metadata = {
        'original_filename': filename,
        'safe_filename': safe_filename,
        'extension': extension,
        'mime_type': detected_mime,
        'size': file_size,
        'is_image': is_image,
        'hashes': file_hashes,
    }

    return file_content, metadata


# Convenience function for avatar uploads
def validate_avatar_upload(uploaded_file) -> Tuple[bytes, Dict[str, any]]:
    """
    Validate avatar image upload with strict image-only requirements.

    Args:
        uploaded_file: Django UploadedFile object

    Returns:
        Tuple of (file_content, metadata_dict)

    Raises:
        ValidationError: If validation fails
    """
    return validate_uploaded_file(
        uploaded_file,
        allowed_types='image',
        require_image=True
    )


# Convenience function for document uploads
def validate_document_upload(uploaded_file) -> Tuple[bytes, Dict[str, any]]:
    """
    Validate document upload (PDF, DOCX, XLSX, TXT).

    Args:
        uploaded_file: Django UploadedFile object

    Returns:
        Tuple of (file_content, metadata_dict)

    Raises:
        ValidationError: If validation fails
    """
    return validate_uploaded_file(
        uploaded_file,
        allowed_types='document',
        require_image=False
    )
