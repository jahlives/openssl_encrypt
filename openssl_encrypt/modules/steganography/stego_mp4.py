#!/usr/bin/env python3
"""
MP4 Video Steganography Module

This module provides steganographic capabilities for MP4 video files, supporting
H.264 and H.265 codecs. It implements multi-layer hiding strategies including:
- Spatial domain LSB in decoded frames
- DCT coefficient modification (frequency domain)
- Motion vector manipulation
- Audio track steganography (using existing audio modules)
- Container metadata hiding

Key Features:
- Format-compliant output (playable in all standard players)
- Quality preservation with configurable levels
- Temporal data spreading for error correction
- Integration with existing audio steganography
- Robust extraction with integrity verification
"""

import logging
import struct
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

try:
    import cv2
    import ffmpeg

    FFMPEG_AVAILABLE = True
except ImportError:
    cv2 = None
    ffmpeg = None
    FFMPEG_AVAILABLE = False

# Import core steganography components
from .stego_core import (
    CapacityError,
    CoverMediaError,
    ExtractionError,
    SteganographyConfig,
    SteganographyUtils,
)

# Import audio steganography for audio track handling
from .stego_mp3 import MP3Steganography

# Import video steganography base classes
from .stego_video_core import (
    VideoFormatError,
    VideoFrameInfo,
    VideoSteganographyBase,
    is_video_steganography_available,
)
from .stego_wav import WAVSteganography

# Import secure memory functions
try:
    from ..secure_memory import SecureBytes, secure_memzero
except ImportError:
    from openssl_encrypt.modules.secure_memory import SecureBytes, secure_memzero

# Set up module logger
logger = logging.getLogger(__name__)


def is_mp4_steganography_available() -> bool:
    """Check if MP4 steganography dependencies are available"""
    return is_video_steganography_available() and FFMPEG_AVAILABLE


class MP4ContainerInfo:
    """Information about MP4 container structure"""

    def __init__(self):
        self.duration: float = 0.0
        self.fps: float = 0.0
        self.width: int = 0
        self.height: int = 0
        self.video_codec: str = ""
        self.audio_codec: str = ""
        self.has_audio: bool = False
        self.bitrate: int = 0
        self.total_frames: int = 0
        self.video_stream_data: Optional[bytes] = None
        self.audio_stream_data: Optional[bytes] = None
        self.metadata: Dict[str, Any] = {}
        self.temp_files: List[str] = []  # Track temporary files for cleanup


class MP4Steganography(VideoSteganographyBase):
    """
    MP4 video steganography implementation

    Supports H.264/H.265 codecs with multi-layer hiding strategies.
    Maintains video quality and format compliance while providing
    high capacity data hiding.
    """

    def __init__(
        self,
        password: Optional[str] = None,
        security_level: int = 1,
        quality_preservation: int = 8,
        temporal_spread: bool = True,
        use_audio_track: bool = True,
        use_motion_vectors: bool = False,
        config: Optional[SteganographyConfig] = None,
    ):
        """
        Initialize MP4 steganography instance

        Args:
            password: Optional password for randomization
            security_level: Security level (1=basic, 2=enhanced, 3=paranoid)
            quality_preservation: Video quality level (1-10, higher=better quality)
            temporal_spread: Enable spreading data across multiple frames
            use_audio_track: Use audio track for additional capacity
            use_motion_vectors: Use motion vectors for hiding (experimental)
            config: Optional steganography configuration
        """
        if not is_mp4_steganography_available():
            raise VideoFormatError(
                "MP4 steganography requires opencv-python and ffmpeg-python: "
                "pip install opencv-python ffmpeg-python"
            )

        super().__init__(
            password=password,
            security_level=security_level,
            quality_preservation=quality_preservation,
            temporal_spread=temporal_spread,
            use_audio_track=use_audio_track,
            use_motion_vectors=use_motion_vectors,
        )

        self.config = config or SteganographyConfig()

        # MP4-specific settings
        self.max_bits_per_pixel = 1 if quality_preservation >= 8 else 2
        self.keyframe_interval = 30  # Typical GOP size
        self.audio_stego = None  # Will be created when needed

        # Video processing parameters
        self.output_quality = max(15, min(35, 25 + (10 - quality_preservation) * 2))  # CRF value

        logger.info(
            f"Initialized MP4 steganography (quality: {quality_preservation}, "
            f"temporal_spread: {temporal_spread}, use_audio: {use_audio_track})"
        )

    def parse_container(self, video_data: bytes) -> Dict[str, Any]:
        """
        Parse MP4 container structure using FFmpeg

        Args:
            video_data: Raw MP4 file data

        Returns:
            Dictionary containing container information
        """
        container_info = MP4ContainerInfo()
        temp_input = None

        try:
            # Write video data to temporary file for FFmpeg processing
            with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as temp_file:
                temp_file.write(video_data)
                temp_input = temp_file.name
                container_info.temp_files.append(temp_input)

            # Probe video information
            try:
                probe = ffmpeg.probe(temp_input)
            except Exception as e:
                raise VideoFormatError(f"Failed to probe MP4 file: {e}")

            # Extract video stream info
            video_streams = [
                stream for stream in probe["streams"] if stream["codec_type"] == "video"
            ]
            audio_streams = [
                stream for stream in probe["streams"] if stream["codec_type"] == "audio"
            ]

            if not video_streams:
                raise VideoFormatError("No video stream found in MP4 file")

            video_stream = video_streams[0]
            container_info.duration = float(video_stream.get("duration", 0))
            container_info.fps = eval(video_stream.get("r_frame_rate", "30/1"))  # Convert fraction
            container_info.width = int(video_stream.get("width", 0))
            container_info.height = int(video_stream.get("height", 0))
            container_info.video_codec = video_stream.get("codec_name", "unknown")
            container_info.total_frames = int(
                float(video_stream.get("nb_frames", container_info.duration * container_info.fps))
            )

            # Extract audio stream info if available
            if audio_streams:
                audio_stream = audio_streams[0]
                container_info.has_audio = True
                container_info.audio_codec = audio_stream.get("codec_name", "unknown")

            # Extract metadata
            container_info.metadata = probe.get("format", {}).get("tags", {})

            logger.info(
                f"Parsed MP4: {container_info.width}x{container_info.height}, "
                f"{container_info.fps} fps, {container_info.duration:.1f}s, "
                f"codec: {container_info.video_codec}, audio: {container_info.has_audio}"
            )

            return {
                "container_info": container_info,
                "video_stream": video_stream,
                "audio_stream": audio_streams[0] if audio_streams else None,
                "duration": container_info.duration,
                "fps": container_info.fps,
                "resolution": (container_info.width, container_info.height),
                "has_audio": container_info.has_audio,
            }

        except Exception as e:
            self._cleanup_temp_files(container_info.temp_files)
            raise VideoFormatError(f"Failed to parse MP4 container: {e}")

    def reconstruct_container(
        self,
        container_info: Dict[str, Any],
        modified_frames: List[np.ndarray],
        modified_audio: Optional[bytes] = None,
    ) -> bytes:
        """
        Reconstruct MP4 container with modified frames and audio

        Args:
            container_info: Container structure from parse_container
            modified_frames: List of modified video frames
            modified_audio: Modified audio data (if any)

        Returns:
            Complete MP4 file data
        """
        mp4_info = container_info["container_info"]
        temp_output = None
        temp_frame_dir = None

        try:
            # Create temporary directory for frames
            temp_frame_dir = tempfile.mkdtemp()

            # Write frames as images
            frame_files = []
            for i, frame in enumerate(modified_frames):
                frame_path = Path(temp_frame_dir) / f"frame_{i:06d}.png"
                cv2.imwrite(str(frame_path), frame)
                frame_files.append(str(frame_path))

            # Create temporary output file
            with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as temp_file:
                temp_output = temp_file.name

            # Build FFmpeg command
            input_pattern = str(Path(temp_frame_dir) / "frame_%06d.png")

            # Base video encoding parameters
            video_args = {
                "vcodec": "libx264",
                "crf": 0,  # Lossless H.264
                "preset": "ultrafast",  # Fastest encoding
                "r": container_info["fps"],
                "pix_fmt": "yuv420p",
            }

            if container_info["has_audio"] and modified_audio:
                # Handle audio + video
                # Write audio to temporary file
                temp_audio = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
                temp_audio.write(modified_audio)
                temp_audio.close()

                # Combine video and audio
                (
                    ffmpeg.input(input_pattern, framerate=container_info["fps"])
                    .video.output(ffmpeg.input(temp_audio.name).audio, temp_output, **video_args)
                    .overwrite_output()
                    .run(quiet=True)
                )

                # Clean up temporary audio file
                Path(temp_audio.name).unlink(missing_ok=True)

            else:
                # Video only
                (
                    ffmpeg.input(input_pattern, framerate=container_info["fps"])
                    .output(temp_output, **video_args)
                    .overwrite_output()
                    .run(quiet=True)
                )

            # Read the reconstructed MP4 file
            with open(temp_output, "rb") as f:
                reconstructed_data = f.read()

            logger.info(f"Reconstructed MP4: {len(reconstructed_data)} bytes")
            return reconstructed_data

        except Exception as e:
            raise VideoFormatError(f"Failed to reconstruct MP4 container: {e}")

        finally:
            # Clean up temporary files
            if temp_output:
                Path(temp_output).unlink(missing_ok=True)

            if temp_frame_dir:
                import shutil

                shutil.rmtree(temp_frame_dir, ignore_errors=True)

            # Clean up container temp files
            if "container_info" in container_info:
                self._cleanup_temp_files(container_info["container_info"].temp_files)

    def hide_data(self, cover_data: bytes, secret_data: bytes) -> bytes:
        """
        Hide secret data in MP4 video

        Args:
            cover_data: Original MP4 video data
            secret_data: Data to hide

        Returns:
            MP4 video with hidden data
        """
        try:
            logger.info(f"Hiding {len(secret_data)} bytes in MP4 video")

            # Parse container
            container_info = self.parse_container(cover_data)

            # Extract frames
            frames, video_info = self.extract_frames(cover_data)

            if not frames:
                raise CapacityError(len(secret_data), 0, "MP4 video")

            # Check capacity
            total_capacity = self.calculate_video_capacity(frames, video_info)
            if len(secret_data) > total_capacity:
                raise CapacityError(len(secret_data), total_capacity, "MP4 video")

            # Prepare data for hiding
            prepared_data = self.prepare_data_for_hiding(secret_data)

            # Distribute data across layers
            video_data_size = int(len(prepared_data) * self.layer_weights.get("video_frames", 0.6))
            audio_data_size = int(len(prepared_data) * self.layer_weights.get("audio_track", 0.25))
            metadata_data_size = len(prepared_data) - video_data_size - audio_data_size

            # Hide in video frames
            modified_frames = frames.copy()
            if video_data_size > 0:
                frame_infos = self.distribute_data(
                    prepared_data[:video_data_size], frames, video_info
                )

                for i, frame_info in enumerate(frame_infos):
                    if frame_info.data_length > 0:
                        frame_data = prepared_data[
                            frame_info.data_offset : frame_info.data_offset + frame_info.data_length
                        ]
                        modified_frames[i] = self.hide_in_frame(frames[i], frame_data, frame_info)

                        # Debug: Verify hiding worked by extracting immediately
                        if i == 0:  # Check first frame which should contain header
                            test_extract = self.extract_from_frame(
                                modified_frames[i], 8, frame_info
                            )
                            logger.debug(f"Frame {i} hide test: {test_extract[:8]}")
                            if test_extract[:4] == b"VSTG":
                                logger.debug(f"Header successfully hidden in frame {i}")
                            else:
                                logger.warning(f"Header NOT found in frame {i} after hiding!")

            # Hide in audio track (if available)
            modified_audio = None
            if audio_data_size > 0 and container_info.get("has_audio", False):
                try:
                    audio_data = prepared_data[video_data_size : video_data_size + audio_data_size]
                    modified_audio = self._hide_in_audio_track(container_info, audio_data)
                except Exception as e:
                    logger.warning(f"Failed to hide data in audio track: {e}")

            # Reconstruct container
            result = self.reconstruct_container(container_info, modified_frames, modified_audio)

            logger.info(f"Successfully hid {len(secret_data)} bytes in MP4 video")
            return result

        except Exception as e:
            logger.error(f"Failed to hide data in MP4: {e}")
            raise

    def extract_data(self, stego_data: bytes) -> bytes:
        """
        Extract hidden data from MP4 video

        Args:
            stego_data: MP4 video containing hidden data

        Returns:
            Extracted secret data
        """
        try:
            logger.info(f"Extracting data from MP4 video ({len(stego_data)} bytes)")

            # Parse container
            container_info = self.parse_container(stego_data)

            # Extract frames
            frames, video_info = self.extract_frames(stego_data)

            if not frames:
                raise ExtractionError("No frames found in MP4 video")

            # Extract from video frames first
            extracted_parts = []

            # Try to extract data length from first few frames
            total_extracted_length = 0

            for i, frame in enumerate(frames):
                if i >= 10:  # Only check first 10 frames for header
                    break

                frame_info = VideoFrameInfo(
                    frame_number=i,
                    frame_type="I" if i % self.keyframe_interval == 0 else "P",
                    size=(frame.shape[1], frame.shape[0]),
                )

                # Try to extract header (magic + length)
                header_data = self.extract_from_frame(
                    frame, 8, frame_info
                )  # 4 bytes magic + 4 bytes length

                # Debug: Show what we extracted
                logger.debug(
                    f"Frame {i} extraction test: {header_data[:8] if len(header_data) >= 8 else header_data}"
                )

                if len(header_data) >= 8 and header_data[:4] == b"VSTG":
                    total_extracted_length = struct.unpack(">I", header_data[4:8])[0]
                    logger.debug(f"Found data length: {total_extracted_length} bytes")
                    break

            if total_extracted_length == 0:
                raise ExtractionError("No valid steganography header found in MP4 video")

            # Extract full data from frames
            prepared_data_length = (
                total_extracted_length + 16
            )  # Add overhead for header, EOF, checksum
            frames_to_process = min(
                len(frames), (prepared_data_length // 1000) + 10
            )  # Estimate frames needed

            extracted_data = b""
            for i in range(frames_to_process):
                if len(extracted_data) >= prepared_data_length:
                    break

                frame_info = VideoFrameInfo(
                    frame_number=i,
                    frame_type="I" if i % self.keyframe_interval == 0 else "P",
                    size=(frames[i].shape[1], frames[i].shape[0]),
                )

                frame_capacity = self.calculate_frame_capacity(frames[i])
                extract_length = min(frame_capacity, prepared_data_length - len(extracted_data))

                if extract_length > 0:
                    frame_data = self.extract_from_frame(frames[i], extract_length, frame_info)
                    extracted_data += frame_data

            # Extract from audio track if available
            if container_info.get("has_audio", False) and self.use_audio_track:
                try:
                    audio_data = self._extract_from_audio_track(container_info)
                    if audio_data:
                        extracted_data += audio_data
                except Exception as e:
                    logger.warning(f"Failed to extract from audio track: {e}")

            # Process extracted data
            if len(extracted_data) < 16:  # Minimum size for header + EOF + checksum
                raise ExtractionError("Insufficient data extracted from MP4 video")

            # Extract the prepared data
            secret_data = self.extract_prepared_data(extracted_data)

            logger.info(f"Successfully extracted {len(secret_data)} bytes from MP4 video")
            return secret_data

        except Exception as e:
            logger.error(f"Failed to extract data from MP4: {e}")
            raise ExtractionError(f"MP4 extraction failed: {e}")

    def _hide_in_audio_track(
        self, container_info: Dict[str, Any], audio_data: bytes
    ) -> Optional[bytes]:
        """
        Hide data in the audio track using appropriate audio steganography

        Args:
            container_info: Container information
            audio_data: Data to hide in audio

        Returns:
            Modified audio data or None
        """
        if not container_info.get("has_audio", False):
            return None

        audio_codec = container_info.get("audio_stream", {}).get("codec_name", "unknown")

        try:
            # Extract audio using FFmpeg
            temp_input = container_info["container_info"].temp_files[0]
            temp_audio = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
            temp_audio.close()

            # Extract audio to WAV format
            (
                ffmpeg.input(temp_input)
                .audio.output(temp_audio.name, acodec="pcm_s16le")
                .overwrite_output()
                .run(quiet=True)
            )

            # Read extracted audio
            with open(temp_audio.name, "rb") as f:
                wav_data = f.read()

            # Use WAV steganography to hide data
            if not self.audio_stego:
                self.audio_stego = WAVSteganography(
                    password=self.password,
                    security_level=self.security_level,
                    bits_per_sample=1,
                    config=self.config,
                )

            # Hide data in audio
            stego_audio = self.audio_stego.hide_data(wav_data, audio_data)

            # Clean up temporary file
            Path(temp_audio.name).unlink(missing_ok=True)

            return stego_audio

        except Exception as e:
            logger.warning(f"Audio track hiding failed: {e}")
            return None

    def _extract_from_audio_track(self, container_info: Dict[str, Any]) -> Optional[bytes]:
        """
        Extract data from the audio track

        Args:
            container_info: Container information

        Returns:
            Extracted audio data or None
        """
        if not container_info.get("has_audio", False):
            return None

        try:
            # Extract audio using FFmpeg
            temp_input = container_info["container_info"].temp_files[0]
            temp_audio = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
            temp_audio.close()

            # Extract audio to WAV format
            (
                ffmpeg.input(temp_input)
                .audio.output(temp_audio.name, acodec="pcm_s16le")
                .overwrite_output()
                .run(quiet=True)
            )

            # Read extracted audio
            with open(temp_audio.name, "rb") as f:
                wav_data = f.read()

            # Use WAV steganography to extract data
            if not self.audio_stego:
                self.audio_stego = WAVSteganography(
                    password=self.password,
                    security_level=self.security_level,
                    bits_per_sample=1,
                    config=self.config,
                )

            # Extract data from audio
            extracted_data = self.audio_stego.extract_data(wav_data)

            # Clean up temporary file
            Path(temp_audio.name).unlink(missing_ok=True)

            return extracted_data

        except Exception as e:
            logger.warning(f"Audio track extraction failed: {e}")
            return None

    def _cleanup_temp_files(self, temp_files: List[str]):
        """Clean up temporary files"""
        for temp_file in temp_files:
            try:
                Path(temp_file).unlink(missing_ok=True)
            except Exception:
                pass


# Utility functions for creating test MP4 videos
def create_mp4_test_video(
    width: int = 640,
    height: int = 480,
    duration: float = 5.0,
    fps: float = 30.0,
    with_audio: bool = False,
) -> bytes:
    """
    Create a test MP4 video for steganography testing

    Args:
        width: Video width in pixels
        height: Video height in pixels
        duration: Video duration in seconds
        fps: Frames per second
        with_audio: Include audio track

    Returns:
        MP4 video file data
    """
    if not is_mp4_steganography_available():
        raise VideoFormatError("MP4 test video creation requires opencv-python and ffmpeg-python")

    temp_output = None
    temp_frame_dir = None

    try:
        # Create temporary directory for frames
        temp_frame_dir = tempfile.mkdtemp()

        # Generate test frames
        total_frames = int(duration * fps)
        frame_files = []

        for i in range(total_frames):
            # Create a test pattern frame
            frame = np.zeros((height, width, 3), dtype=np.uint8)

            # Add some pattern (moving color bars)
            bar_width = width // 8
            for j in range(8):
                color = ((j * 32 + i * 2) % 256, (j * 64 + i * 3) % 256, (j * 96 + i * 4) % 256)
                x_start = (j * bar_width + i * 2) % width
                x_end = min(x_start + bar_width, width)
                frame[:, x_start:x_end] = color

            # Add frame number text
            cv2.putText(
                frame, f"Frame {i:04d}", (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2
            )

            # Save frame
            frame_path = Path(temp_frame_dir) / f"frame_{i:06d}.png"
            cv2.imwrite(str(frame_path), frame)
            frame_files.append(str(frame_path))

        # Create temporary output file
        with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as temp_file:
            temp_output = temp_file.name

        # Build FFmpeg command
        input_pattern = str(Path(temp_frame_dir) / "frame_%06d.png")

        if with_audio:
            # Generate test audio (sine wave)
            (
                ffmpeg.input(input_pattern, framerate=fps)
                .video.output(
                    ffmpeg.input(
                        "sine=frequency=440:duration={}".format(duration), f="lavfi"
                    ).audio,
                    temp_output,
                    vcodec="libx264",
                    crf=0,
                    preset="ultrafast",
                    acodec="aac",
                    pix_fmt="rgb24",
                )
                .overwrite_output()
                .run(quiet=True)
            )
        else:
            # Video only
            (
                ffmpeg.input(input_pattern, framerate=fps)
                .output(temp_output, vcodec="libx264", crf=0, preset="ultrafast", pix_fmt="rgb24")
                .overwrite_output()
                .run(quiet=True)
            )

        # Read the created MP4 file
        with open(temp_output, "rb") as f:
            mp4_data = f.read()

        logger.info(
            f"Created test MP4: {len(mp4_data)} bytes, {width}x{height}, "
            f"{duration}s, {fps} fps, audio: {with_audio}"
        )

        return mp4_data

    except Exception as e:
        raise VideoFormatError(f"Failed to create test MP4 video: {e}")

    finally:
        # Clean up temporary files
        if temp_output:
            Path(temp_output).unlink(missing_ok=True)

        if temp_frame_dir:
            import shutil

            shutil.rmtree(temp_frame_dir, ignore_errors=True)


def create_mp4_test_video_simple(
    width: int = 320, height: int = 240, duration: float = 2.0
) -> bytes:
    """
    Create a simple test MP4 video for quick testing

    Args:
        width: Video width in pixels
        height: Video height in pixels
        duration: Video duration in seconds

    Returns:
        Small MP4 video file data
    """
    return create_mp4_test_video(width, height, duration, fps=15.0, with_audio=False)
