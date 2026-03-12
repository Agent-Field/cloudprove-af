"""
Media Provider Abstraction for AgentField

Provides a unified interface for different media generation backends:
- Fal.ai (Flux, SDXL, Whisper, TTS, Video models)
- OpenRouter (via LiteLLM)
- OpenAI DALL-E (via LiteLLM)
- Future: ElevenLabs, Replicate, etc.

Each provider implements the same interface, making it easy to swap
backends or add new ones without changing agent code.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Literal, Optional, Union

from agentfield.multimodal_response import (
    AudioOutput,
    FileOutput,
    ImageOutput,
    MultimodalResponse,
)


# Fal image size presets
FalImageSize = Literal[
    "square_hd",      # 1024x1024
    "square",         # 512x512
    "portrait_4_3",   # 768x1024
    "portrait_16_9",  # 576x1024
    "landscape_4_3",  # 1024x768
    "landscape_16_9", # 1024x576
]


class MediaProvider(ABC):
    """
    Abstract base class for media generation providers.

    Subclass this to add support for new image/audio generation backends.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name for identification."""
        pass

    @property
    @abstractmethod
    def supported_modalities(self) -> List[str]:
        """List of supported modalities: 'image', 'audio', 'video'."""
        pass

    @abstractmethod
    async def generate_image(
        self,
        prompt: str,
        model: Optional[str] = None,
        size: str = "1024x1024",
        quality: str = "standard",
        **kwargs,
    ) -> MultimodalResponse:
        """
        Generate an image from a text prompt.

        Args:
            prompt: Text description of the image
            model: Model to use (provider-specific)
            size: Image dimensions or preset
            quality: Quality level
            **kwargs: Provider-specific options

        Returns:
            MultimodalResponse with generated image(s)
        """
        pass

    @abstractmethod
    async def generate_audio(
        self,
        text: str,
        model: Optional[str] = None,
        voice: str = "alloy",
        format: str = "wav",
        **kwargs,
    ) -> MultimodalResponse:
        """
        Generate audio/speech from text.

        Args:
            text: Text to convert to speech
            model: TTS model to use
            voice: Voice identifier
            format: Audio format
            **kwargs: Provider-specific options

        Returns:
            MultimodalResponse with generated audio
        """
        pass

    async def generate_video(
        self,
        prompt: str,
        model: Optional[str] = None,
        image_url: Optional[str] = None,
        **kwargs,
    ) -> MultimodalResponse:
        """
        Generate video from text or image.

        Args:
            prompt: Text description for video
            model: Video model to use
            image_url: Optional input image for image-to-video
            **kwargs: Provider-specific options

        Returns:
            MultimodalResponse with generated video
        """
        raise NotImplementedError(f"{self.name} does not support video generation")


class FalProvider(MediaProvider):
    """
    Fal.ai provider for image, audio, and video generation.

    Image Models:
    - fal-ai/flux/dev - FLUX.1 [dev], 12B params, high quality (default)
    - fal-ai/flux/schnell - FLUX.1 [schnell], fast 1-4 step generation
    - fal-ai/flux-pro/v1.1-ultra - FLUX Pro Ultra, up to 2K resolution
    - fal-ai/fast-sdxl - Fast SDXL
    - fal-ai/recraft-v3 - SOTA text-to-image
    - fal-ai/stable-diffusion-v35-large - SD 3.5 Large

    Video Models:
    - fal-ai/minimax-video/image-to-video - Image to video
    - fal-ai/luma-dream-machine - Luma Dream Machine
    - fal-ai/kling-video/v1/standard - Kling 1.0

    Audio Models:
    - fal-ai/whisper - Speech to text
    - Custom TTS deployments

    Requires FAL_KEY environment variable or explicit api_key.

    Example:
        provider = FalProvider(api_key="...")

        # Generate image
        result = await provider.generate_image(
            "A sunset over mountains",
            model="fal-ai/flux/dev",
            image_size="landscape_16_9",
            num_images=2
        )
        result.images[0].save("sunset.png")

        # Generate video from image
        result = await provider.generate_video(
            "Camera slowly pans across the scene",
            model="fal-ai/minimax-video/image-to-video",
            image_url="https://example.com/image.jpg"
        )
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Fal provider.

        Args:
            api_key: Fal.ai API key. If not provided, uses FAL_KEY env var.
        """
        self._api_key = api_key
        self._client = None

    @property
    def name(self) -> str:
        return "fal"

    @property
    def supported_modalities(self) -> List[str]:
        return ["image", "audio", "video"]

    def _get_client(self):
        """Lazy initialization of fal client."""
        if self._client is None:
            try:
                import fal_client

                if self._api_key:
                    import os
                    os.environ["FAL_KEY"] = self._api_key

                self._client = fal_client
            except ImportError:
                raise ImportError(
                    "fal-client is not installed. Install it with: pip install fal-client"
                )
        return self._client

    def _parse_image_size(
        self, size: str
    ) -> Union[str, Dict[str, int]]:
        """
        Parse image size into fal format.

        Args:
            size: Either a preset like "landscape_16_9" or dimensions like "1024x768"

        Returns:
            Fal-compatible image_size (string preset or dict with width/height)
        """
        # Check if it's a fal preset
        fal_presets = {
            "square_hd", "square", "portrait_4_3", "portrait_16_9",
            "landscape_4_3", "landscape_16_9"
        }
        if size in fal_presets:
            return size

        # Parse WxH format
        if "x" in size.lower():
            parts = size.lower().split("x")
            try:
                width, height = int(parts[0]), int(parts[1])
                return {"width": width, "height": height}
            except ValueError:
                pass

        # Default to square_hd
        return "square_hd"

    async def generate_image(
        self,
        prompt: str,
        model: Optional[str] = None,
        size: str = "square_hd",
        quality: str = "standard",
        num_images: int = 1,
        seed: Optional[int] = None,
        guidance_scale: Optional[float] = None,
        num_inference_steps: Optional[int] = None,
        **kwargs,
    ) -> MultimodalResponse:
        """
        Generate image using Fal.ai.

        Args:
            prompt: Text prompt for image generation
            model: Fal model ID (defaults to "fal-ai/flux/dev")
            size: Image size - preset ("square_hd", "landscape_16_9") or "WxH"
            quality: "standard" (25 steps) or "hd" (50 steps)
            num_images: Number of images to generate (1-4)
            seed: Random seed for reproducibility
            guidance_scale: Guidance scale for generation
            num_inference_steps: Override inference steps
            **kwargs: Additional fal-specific parameters

        Returns:
            MultimodalResponse with generated images

        Example:
            result = await provider.generate_image(
                "A cyberpunk cityscape at night",
                model="fal-ai/flux/dev",
                size="landscape_16_9",
                num_images=2,
                seed=42
            )
        """
        client = self._get_client()

        # Default model
        if model is None:
            model = "fal-ai/flux/dev"

        # Parse image size
        image_size = self._parse_image_size(size)

        # Determine inference steps based on quality
        if num_inference_steps is None:
            num_inference_steps = 25 if quality == "standard" else 50

        # Build request arguments
        fal_args: Dict[str, Any] = {
            "prompt": prompt,
            "image_size": image_size,
            "num_images": num_images,
            "num_inference_steps": num_inference_steps,
        }

        # Add optional parameters
        if seed is not None:
            fal_args["seed"] = seed
        if guidance_scale is not None:
            fal_args["guidance_scale"] = guidance_scale

        # Merge any additional kwargs
        fal_args.update(kwargs)

        try:
            # Use subscribe_async for queue-based reliable execution
            result = await client.subscribe_async(
                model,
                arguments=fal_args,
                with_logs=False,
            )

            # Extract images from result
            images = []
            if "images" in result:
                for img_data in result["images"]:
                    url = img_data.get("url")
                    # width, height, content_type available but not used currently
                    # _width = img_data.get("width")
                    # _height = img_data.get("height")
                    # _content_type = img_data.get("content_type", "image/png")

                    if url:
                        images.append(
                            ImageOutput(
                                url=url,
                                b64_json=None,
                                revised_prompt=prompt,
                            )
                        )

            # Also check for single image response
            if "image" in result and not images:
                img_data = result["image"]
                url = img_data.get("url") if isinstance(img_data, dict) else img_data
                if url:
                    images.append(
                        ImageOutput(url=url, b64_json=None, revised_prompt=prompt)
                    )

            return MultimodalResponse(
                text=prompt,
                audio=None,
                images=images,
                files=[],
                raw_response=result,
            )

        except Exception as e:
            from agentfield.logger import log_error
            log_error(f"Fal image generation failed: {e}")
            raise

    async def generate_audio(
        self,
        text: str,
        model: Optional[str] = None,
        voice: Optional[str] = None,
        format: str = "wav",
        ref_audio_url: Optional[str] = None,
        speed: float = 1.0,
        **kwargs,
    ) -> MultimodalResponse:
        """
        Generate audio using Fal.ai TTS models.

        For voice cloning, provide a ref_audio_url with a sample of the voice.

        Args:
            text: Text to convert to speech
            model: Fal TTS model (provider-specific)
            voice: Voice identifier or preset
            format: Audio format (wav, mp3)
            ref_audio_url: URL to reference audio for voice cloning
            speed: Speech speed multiplier
            **kwargs: Additional fal-specific parameters (gen_text, ref_text, etc.)

        Returns:
            MultimodalResponse with generated audio

        Note:
            Fal has various TTS models with different APIs. Check the specific
            model documentation for available parameters.
        """
        client = self._get_client()

        # Build request arguments based on model
        fal_args: Dict[str, Any] = {}

        # Common patterns for fal TTS models
        if "gen_text" not in kwargs:
            fal_args["gen_text"] = text
        if ref_audio_url:
            fal_args["ref_audio_url"] = ref_audio_url
        if voice and voice.startswith("http"):
            fal_args["ref_audio_url"] = voice

        # Merge additional kwargs
        fal_args.update(kwargs)

        try:
            result = await client.subscribe_async(
                model,
                arguments=fal_args,
                with_logs=False,
            )

            # Extract audio from result - fal returns audio in various formats
            audio = None
            audio_url = None

            # Check common response patterns
            if "audio_url" in result:
                audio_url = result["audio_url"]
            elif "audio" in result:
                audio_data = result["audio"]
                if isinstance(audio_data, dict):
                    audio_url = audio_data.get("url")
                elif isinstance(audio_data, str):
                    audio_url = audio_data

            if audio_url:
                audio = AudioOutput(
                    url=audio_url,
                    data=None,
                    format=format,
                )

            return MultimodalResponse(
                text=text,
                audio=audio,
                images=[],
                files=[],
                raw_response=result,
            )

        except Exception as e:
            from agentfield.logger import log_error
            log_error(f"Fal audio generation failed: {e}")
            raise

    async def generate_video(
        self,
        prompt: str,
        model: Optional[str] = None,
        image_url: Optional[str] = None,
        duration: Optional[float] = None,
        **kwargs,
    ) -> MultimodalResponse:
        """
        Generate video using Fal.ai video models.

        Args:
            prompt: Text description for the video
            model: Fal video model (defaults to "fal-ai/minimax-video/image-to-video")
            image_url: Input image URL for image-to-video models
            duration: Video duration in seconds (model-dependent)
            **kwargs: Additional fal-specific parameters

        Returns:
            MultimodalResponse with video in files list

        Example:
            # Image to video
            result = await provider.generate_video(
                "Camera slowly pans across the mountain landscape",
                model="fal-ai/minimax-video/image-to-video",
                image_url="https://example.com/mountain.jpg"
            )

            # Text to video
            result = await provider.generate_video(
                "A cat playing with yarn",
                model="fal-ai/kling-video/v1/standard"
            )
        """
        client = self._get_client()

        # Default model
        if model is None:
            model = "fal-ai/minimax-video/image-to-video"

        # Build request arguments
        fal_args: Dict[str, Any] = {
            "prompt": prompt,
        }

        if image_url:
            fal_args["image_url"] = image_url
        if duration:
            fal_args["duration"] = duration

        # Merge additional kwargs
        fal_args.update(kwargs)

        try:
            result = await client.subscribe_async(
                model,
                arguments=fal_args,
                with_logs=False,
            )

            # Extract video from result
            files = []
            video_url = None

            # Check common response patterns
            if "video_url" in result:
                video_url = result["video_url"]
            elif "video" in result:
                video_data = result["video"]
                if isinstance(video_data, dict):
                    video_url = video_data.get("url")
                elif isinstance(video_data, str):
                    video_url = video_data

            if video_url:
                files.append(
                    FileOutput(
                        url=video_url,
                        data=None,
                        mime_type="video/mp4",
                        filename="generated_video.mp4",
                    )
                )

            return MultimodalResponse(
                text=prompt,
                audio=None,
                images=[],
                files=files,
                raw_response=result,
            )

        except Exception as e:
            from agentfield.logger import log_error
            log_error(f"Fal video generation failed: {e}")
            raise

    async def transcribe_audio(
        self,
        audio_url: str,
        model: str = "fal-ai/whisper",
        language: Optional[str] = None,
        **kwargs,
    ) -> MultimodalResponse:
        """
        Transcribe audio to text using Fal's Whisper model.

        Args:
            audio_url: URL to audio file to transcribe
            model: Whisper model (defaults to "fal-ai/whisper")
            language: Optional language hint
            **kwargs: Additional parameters

        Returns:
            MultimodalResponse with transcribed text
        """
        client = self._get_client()

        fal_args: Dict[str, Any] = {
            "audio_url": audio_url,
        }
        if language:
            fal_args["language"] = language
        fal_args.update(kwargs)

        try:
            result = await client.subscribe_async(
                model,
                arguments=fal_args,
                with_logs=False,
            )

            # Extract text from result
            text = ""
            if "text" in result:
                text = result["text"]
            elif "transcription" in result:
                text = result["transcription"]

            return MultimodalResponse(
                text=text,
                audio=None,
                images=[],
                files=[],
                raw_response=result,
            )

        except Exception as e:
            from agentfield.logger import log_error
            log_error(f"Fal transcription failed: {e}")
            raise


class LiteLLMProvider(MediaProvider):
    """
    LiteLLM-based provider for OpenAI, Azure, and other LiteLLM-supported backends.

    Uses LiteLLM's image_generation and speech APIs.

    Image Models:
    - dall-e-3 - OpenAI DALL-E 3
    - dall-e-2 - OpenAI DALL-E 2
    - azure/dall-e-3 - Azure DALL-E

    Audio Models:
    - tts-1 - OpenAI TTS
    - tts-1-hd - OpenAI TTS HD
    - gpt-4o-mini-tts - GPT-4o Mini TTS
    """

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key

    @property
    def name(self) -> str:
        return "litellm"

    @property
    def supported_modalities(self) -> List[str]:
        return ["image", "audio"]

    async def generate_image(
        self,
        prompt: str,
        model: Optional[str] = None,
        size: str = "1024x1024",
        quality: str = "standard",
        style: Optional[str] = None,
        response_format: str = "url",
        **kwargs,
    ) -> MultimodalResponse:
        """Generate image using LiteLLM (DALL-E, Azure DALL-E, etc.)."""
        from agentfield import vision

        model = model or "dall-e-3"

        return await vision.generate_image_litellm(
            prompt=prompt,
            model=model,
            size=size,
            quality=quality,
            style=style,
            response_format=response_format,
            **kwargs,
        )

    async def generate_audio(
        self,
        text: str,
        model: Optional[str] = None,
        voice: str = "alloy",
        format: str = "wav",
        speed: float = 1.0,
        **kwargs,
    ) -> MultimodalResponse:
        """Generate audio using LiteLLM TTS."""
        try:
            import litellm

            litellm.suppress_debug_info = True
        except ImportError:
            raise ImportError(
                "litellm is not installed. Install it with: pip install litellm"
            )

        model = model or "tts-1"

        try:
            response = await litellm.aspeech(
                model=model,
                input=text,
                voice=voice,
                speed=speed,
                **kwargs,
            )

            # Extract audio data
            audio_data = None
            if hasattr(response, "content"):
                import base64

                audio_data = base64.b64encode(response.content).decode("utf-8")

            audio = AudioOutput(
                data=audio_data,
                format=format,
                url=None,
            )

            return MultimodalResponse(
                text=text,
                audio=audio,
                images=[],
                files=[],
                raw_response=response,
            )

        except Exception as e:
            from agentfield.logger import log_error

            log_error(f"LiteLLM audio generation failed: {e}")
            raise


class OpenRouterProvider(MediaProvider):
    """
    OpenRouter provider for image generation via chat completions.

    Uses the modalities parameter with chat completions API for image generation.

    Supports models like:
    - google/gemini-2.5-flash-image-preview
    - Other OpenRouter models with image generation capabilities
    """

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key

    @property
    def name(self) -> str:
        return "openrouter"

    @property
    def supported_modalities(self) -> List[str]:
        return ["image"]  # OpenRouter primarily supports image generation

    async def generate_image(
        self,
        prompt: str,
        model: Optional[str] = None,
        size: str = "1024x1024",
        quality: str = "standard",
        **kwargs,
    ) -> MultimodalResponse:
        """Generate image using OpenRouter's chat completions API."""
        from agentfield import vision

        model = model or "openrouter/google/gemini-2.5-flash-image-preview"

        # Ensure model has openrouter prefix
        if not model.startswith("openrouter/"):
            model = f"openrouter/{model}"

        return await vision.generate_image_openrouter(
            prompt=prompt,
            model=model,
            size=size,
            quality=quality,
            style=None,
            response_format="url",
            **kwargs,
        )

    async def generate_audio(
        self,
        text: str,
        model: Optional[str] = None,
        voice: str = "alloy",
        format: str = "wav",
        **kwargs,
    ) -> MultimodalResponse:
        """OpenRouter doesn't support TTS directly."""
        raise NotImplementedError(
            "OpenRouter doesn't support audio generation. Use LiteLLMProvider or FalProvider."
        )


# Provider registry for easy access
_PROVIDERS: Dict[str, type] = {
    "fal": FalProvider,
    "litellm": LiteLLMProvider,
    "openrouter": OpenRouterProvider,
}


def get_provider(name: str, **kwargs) -> MediaProvider:
    """
    Get a media provider instance by name.

    Args:
        name: Provider name ('fal', 'litellm', 'openrouter')
        **kwargs: Provider-specific initialization arguments

    Returns:
        MediaProvider instance

    Example:
        # Fal provider for Flux
        provider = get_provider("fal", api_key="...")
        result = await provider.generate_image(
            "A sunset over mountains",
            model="fal-ai/flux/dev"
        )

        # LiteLLM provider for DALL-E
        provider = get_provider("litellm")
        result = await provider.generate_image(
            "A sunset over mountains",
            model="dall-e-3"
        )
    """
    if name not in _PROVIDERS:
        raise ValueError(
            f"Unknown provider: {name}. Available: {list(_PROVIDERS.keys())}"
        )
    return _PROVIDERS[name](**kwargs)


def register_provider(name: str, provider_class: type):
    """
    Register a custom media provider.

    Args:
        name: Provider name for lookup
        provider_class: MediaProvider subclass

    Example:
        class ReplicateProvider(MediaProvider):
            ...

        register_provider("replicate", ReplicateProvider)
    """
    if not issubclass(provider_class, MediaProvider):
        raise TypeError("provider_class must be a MediaProvider subclass")
    _PROVIDERS[name] = provider_class
