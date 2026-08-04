"""Locally-generated CAPTCHA images for offline testing."""
import io
import random
import string
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def make_captcha_image(text, width=200, height=60, noise_level=0):
    img = Image.new("RGB", (width, height), color="white")
    draw = ImageDraw.Draw(img)

    font = None
    for candidate in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    ):
        if Path(candidate).exists():
            try:
                font = ImageFont.truetype(candidate, size=32)
                break
            except OSError:
                continue
    if font is None:
        font = ImageFont.load_default()

    bbox = draw.textbbox((0, 0), text, font=font)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]
    draw.text(
        ((width - text_w) / 2, (height - text_h) / 2 - bbox[1]),
        text,
        fill="black",
        font=font,
    )

    if noise_level >= 1:
        random.seed(42)
        for _ in range(width * height // 40):
            x, y = random.randint(0, width - 1), random.randint(0, height - 1)
            draw.point((x, y), fill="black")
    if noise_level >= 2:
        for _ in range(3):
            x1, y1 = random.randint(0, width), random.randint(0, height)
            x2, y2 = random.randint(0, width), random.randint(0, height)
            draw.line((x1, y1, x2, y2), fill="black", width=1)

    return img


def image_to_png_bytes(img):
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def random_captcha_text(length=5):
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=length))
