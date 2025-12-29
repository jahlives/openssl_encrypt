"""Format-specific steganography handlers."""

# Image formats
# Audio formats
from .flac import FLACSteganography
from .image import AdaptiveLSBStego, ImageSteganography, LSBImageStego
from .jpeg import JPEGSteganography
from .mp3 import MP3Steganography
from .tiff import TIFFSteganography
from .wav import WAVSteganography
from .webp import WEBPSteganography

__all__ = [
    # Image handlers
    "ImageSteganography",
    "LSBImageStego",
    "AdaptiveLSBStego",
    "JPEGSteganography",
    "TIFFSteganography",
    "WEBPSteganography",
    # Audio handlers
    "WAVSteganography",
    "FLACSteganography",
    "MP3Steganography",
]
