"""Convert any *.webm in output/ to *.mp4 using imageio-ffmpeg's
bundled binary. Idempotent — re-running overwrites existing mp4s."""

from __future__ import annotations

import pathlib
import subprocess
import sys

import imageio_ffmpeg

OUT = pathlib.Path(__file__).resolve().parent / "output"
FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()


def main() -> int:
    webms = sorted(OUT.glob("*.webm"))
    if not webms:
        print("no webm files in output/")
        return 1
    print(f"== converting {len(webms)} videos with {FFMPEG}")
    converted = 0
    for webm in webms:
        mp4 = webm.with_suffix(".mp4")
        r = subprocess.run(
            [
                FFMPEG,
                "-y", "-loglevel", "error",
                "-i", str(webm),
                "-c:v", "libx264",
                "-preset", "fast",
                "-crf", "23",
                "-pix_fmt", "yuv420p",
                str(mp4),
            ],
            capture_output=True,
        )
        if r.returncode == 0:
            converted += 1
            print(f"  ✓ {mp4.name}  ({mp4.stat().st_size // 1024} KB)")
        else:
            print(f"  ! {webm.name}: {r.stderr.decode()[:200]}")
    print(f"== done: {converted}/{len(webms)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
