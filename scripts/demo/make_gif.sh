#!/bin/sh
# Builds docs/demo.gif and docs/demo.mp4 from made-up demo data.
# Needs: Python 3.10+, Node.js with Playwright (Chromium), ffmpeg.
set -e
cd "$(dirname "$0")"
python3 make_scenes.py
rm -rf frames && node render_frames.js frames
ffmpeg -y -loglevel error -framerate 10 -i frames/f%05d.png -vf "split[a][b];[a]palettegen=max_colors=96[p];[b][p]paletteuse=dither=none" ../../docs/demo.gif
ffmpeg -y -loglevel error -framerate 10 -i frames/f%05d.png -c:v libx264 -pix_fmt yuv420p -r 30 ../../docs/demo.mp4
rm -rf frames scenes.json
ls -la ../../docs/demo.gif ../../docs/demo.mp4
