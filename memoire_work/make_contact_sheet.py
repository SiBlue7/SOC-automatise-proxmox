from pathlib import Path

from PIL import Image, ImageDraw


files = sorted(Path("memoire_work/rendered").glob("*.png"), key=lambda p: int(p.stem.split("-")[1]))
cell = (360, 510)
pad = 20
cols = 4
rows = (len(files) + cols - 1) // cols
sheet = Image.new("RGB", (cols * (cell[0] + pad) + pad, rows * (cell[1] + pad) + pad), "white")
draw = ImageDraw.Draw(sheet)

for idx, path in enumerate(files):
    im = Image.open(path).convert("RGB")
    im.thumbnail((cell[0], cell[1] - 28))
    x = pad + (idx % cols) * (cell[0] + pad)
    y = pad + (idx // cols) * (cell[1] + pad)
    draw.text((x, y), path.stem, fill=(0, 0, 0))
    sheet.paste(im, (x, y + 28))

sheet.save("memoire_work/render_contact_sheet.png")
print(f"{len(files)} pages -> memoire_work/render_contact_sheet.png")
