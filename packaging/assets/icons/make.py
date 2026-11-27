import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))


def w(n, s):
    with open(n, 'w', encoding='utf-8') as f:
        f.write(s.strip() + '\n')


DEFS = '''<defs>
<linearGradient id="et-strut" x1="40" y1="200" x2="200" y2="40" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#2D5BE0"/><stop offset=".55" stop-color="#1F8FE6"/><stop offset="1" stop-color="#3FD0EE"/></linearGradient>
<linearGradient id="et-strut-edge" x1="40" y1="200" x2="200" y2="40" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#1A3A9E"/><stop offset="1" stop-color="#156FAE"/></linearGradient>
<radialGradient id="et-top" cx=".36" cy=".3" r=".8"><stop offset="0" stop-color="#B8F6FF"/><stop offset=".45" stop-color="#3FD2F0"/><stop offset="1" stop-color="#1590D8"/></radialGradient>
<radialGradient id="et-left" cx=".36" cy=".3" r=".8"><stop offset="0" stop-color="#B9D4FF"/><stop offset=".45" stop-color="#4F8BFA"/><stop offset="1" stop-color="#2648C9"/></radialGradient>
<radialGradient id="et-right" cx=".36" cy=".3" r=".8"><stop offset="0" stop-color="#B5F7EA"/><stop offset=".45" stop-color="#2FCDB6"/><stop offset="1" stop-color="#0F8F98"/></radialGradient>
<filter id="et-shadow" x="-20%" y="-20%" width="140%" height="150%"><feDropShadow dx="0" dy="6" stdDeviation="7" flood-color="#0B2A66" flood-opacity=".26"/></filter>
</defs>'''


def triad(top=(128, 58), left=(54, 182), right=(202, 182), r=32, sw=24,
          strut='url(#et-strut)', edge='url(#et-strut-edge)'):
    (tx, ty), (lx, ly), (rx, ry) = top, left, right
    tri = f'M{tx} {ty} L{lx} {ly} L{rx} {ry} Z'
    hl = r * 0.69
    arcs = ''.join(
        f'<path d="M{x - hl:.1f} {y - r * .25:.1f} A{hl:.1f} {hl:.1f} 0 0 1 {x - r * .12:.1f} {y - hl:.1f}"/>'
        for x, y in (top, left, right))
    rims = ''.join(f'<circle cx="{x}" cy="{y}" r="{r - 1}"/>' for x, y in (top, left, right))
    return f'''<g filter="url(#et-shadow)">
<path d="{tri}" fill="none" stroke="{edge}" stroke-width="{sw + 4}" stroke-linejoin="round" transform="translate(0 3)"/>
<path d="{tri}" fill="none" stroke="{strut}" stroke-width="{sw}" stroke-linejoin="round"/>
<circle cx="{tx}" cy="{ty}" r="{r}" fill="url(#et-top)"/>
<circle cx="{lx}" cy="{ly}" r="{r}" fill="url(#et-left)"/>
<circle cx="{rx}" cy="{ry}" r="{r}" fill="url(#et-right)"/>
<g fill="none" stroke="#FFFFFF" stroke-opacity=".55" stroke-width="{max(2.5, r / 8):.1f}" stroke-linecap="round">{arcs}</g>
<g fill="none" stroke="#062A6B" stroke-opacity=".18" stroke-width="2">{rims}</g>
</g>'''


w('app.svg', f'<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256">{DEFS}{triad()}</svg>')

TILE_DEFS = DEFS.replace('</defs>', '''<linearGradient id="et-tile" x1="128" y1="24" x2="128" y2="232" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#2F7BF5"/><stop offset="1" stop-color="#1238A6"/></linearGradient>
<linearGradient id="et-tile-gloss" x1="128" y1="24" x2="128" y2="130" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#FFFFFF" stop-opacity=".22"/><stop offset="1" stop-color="#FFFFFF" stop-opacity="0"/></linearGradient>
<linearGradient id="et-strut-l" x1="40" y1="200" x2="200" y2="40" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#A9C8FF"/><stop offset="1" stop-color="#D2F7FF"/></linearGradient>
<filter id="et-tile-shadow" x="-10%" y="-10%" width="120%" height="125%"><feDropShadow dx="0" dy="5" stdDeviation="5" flood-color="#000000" flood-opacity=".28"/></filter>
</defs>''')
SQ = 'M128 24C211 24 232 45 232 128S211 232 128 232 24 211 24 128 45 24 128 24Z'
inner = triad((128, 78), (74, 170), (182, 170), 24, 15, strut='url(#et-strut-l)', edge='#0E2C86')
w('app-macos.svg',
  f'<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256">{TILE_DEFS}'
  f'<g filter="url(#et-tile-shadow)"><path d="{SQ}" fill="url(#et-tile)"/><path d="{SQ}" fill="url(#et-tile-gloss)"/>'
  f'<path d="{SQ}" fill="none" stroke="#FFFFFF" stroke-opacity=".18" stroke-width="2"/></g>{inner}</svg>')


def small(name, size, top, left, right, rad, sw):
    (tx, ty), (lx, ly), (rx, ry) = top, left, right
    w(name, f'''<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 {size} {size}">
<defs><linearGradient id="s-strut" x1="0" y1="{size}" x2="{size}" y2="0" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#2D5BE0"/><stop offset="1" stop-color="#22A9E8"/></linearGradient>
<linearGradient id="s-t" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#5FDDF6"/><stop offset="1" stop-color="#1590D8"/></linearGradient>
<linearGradient id="s-l" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#6E9DFB"/><stop offset="1" stop-color="#2648C9"/></linearGradient>
<linearGradient id="s-r" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#4FDCC6"/><stop offset="1" stop-color="#0F8F98"/></linearGradient></defs>
<path d="M{tx} {ty} L{lx} {ly} L{rx} {ry} Z" fill="none" stroke="url(#s-strut)" stroke-width="{sw}" stroke-linejoin="round"/>
<circle cx="{tx}" cy="{ty}" r="{rad}" fill="url(#s-t)"/><circle cx="{lx}" cy="{ly}" r="{rad}" fill="url(#s-l)"/><circle cx="{rx}" cy="{ry}" r="{rad}" fill="url(#s-r)"/></svg>''')


small('app-16.svg', 16, (8, 3), (3, 13), (13, 13), 3, 2)
small('app-24.svg', 24, (12, 5), (5, 19), (19, 19), 4.5, 2)
small('app-32.svg', 32, (16, 7), (7, 24), (25, 24), 6, 3)


def tray(size, state, ink):
    # Pixel-aligned geometry: node centres on integer coordinates, 2 px struts.
    if size == 16:
        t, l, r, rad, sw, ring = (8, 3), (3, 13), (13, 13), 2.75, 2, 1.5
    else:
        t, l, r, rad, sw, ring = (12, 5), (5, 19), (19, 19), 4, 2, 1.75
    (tx, ty), (lx, ly), (rx, ry) = t, l, r
    dots = ''.join(f'<circle cx="{x}" cy="{y}" r="{rad}" fill="{ink}"/>' for x, y in (t, l, r))
    if state == 'connected':
        body = (f'<path d="M{tx} {ty} L{lx} {ly} L{rx} {ry} Z" fill="none" stroke="{ink}" '
                f'stroke-width="{sw}" stroke-linejoin="round"/>' + dots)
    elif state == 'connecting':
        def mid(a, b, f):
            return a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f
        stubs = ''
        for a, b in ((t, l), (l, r), (r, t)):
            p, q = mid(a, b, .38), mid(a, b, .62)
            stubs += f'M{p[0]:.2f} {p[1]:.2f} L{q[0]:.2f} {q[1]:.2f} '
        body = dots + f'<path d="{stubs}" stroke="{ink}" stroke-width="{sw}" stroke-linecap="butt"/>'
    else:
        body = ''.join(f'<circle cx="{x}" cy="{y}" r="{rad - ring / 2 + .25}" fill="none" stroke="{ink}" stroke-width="{ring}"/>'
                       for x, y in (t, l, r))
    return f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 {size} {size}">{body}</svg>'


os.makedirs('tray', exist_ok=True)
for theme, ink in (('light', '#1B1B1B'), ('dark', '#FFFFFF')):
    for size in (16, 24):
        for st in ('connected', 'connecting', 'disconnected'):
            w(f'tray/{theme}-{size}-{st}.svg', tray(size, st, ink))
print(sorted(os.listdir('.')), len(os.listdir('tray')))
