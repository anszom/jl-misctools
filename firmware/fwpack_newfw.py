#
# New-Firmware packer: the inverse of fwunpack_newfw.py.
#
# It reads an unpack directory (fwpack.yaml + the dumped files/partitions) and
# rebuilds a flash image, re-deriving every CRC and re-applying the ENC/SFC
# ciphers. It is a faithful *serializer*: it lays out exactly what the manifest
# describes. All "smart" decisions - resizing app.bin, moving/shrinking the VM
# partition, blanking NVM - are done by editing the manifest and the on-disk
# files before packing, NOT by this tool.
#
# Layout / addressing (mirrors the unpacker precisely):
#   * flash header: 32 bytes at base_offset, ENC-scrambled (key 0xFFFF); vid/pid
#     are stored raw while the CRC covers the fully-descrambled header.
#   * top area: a table of 32-byte headers right after the flash header, each
#     ENC-scrambled independently. Entry data lives at (offset + base):
#       - spl   : original bankcb-scrambled SPL bytes, placed verbatim
#       - plain : plaintext blob (e.g. isd_config.ini, holds the chipkey), verbatim
#       - app-area : header only; its data IS the SFC app area (placed separately)
#       - reserved : header only; partition data (if any) placed after encryption
#   * app area: a daisy chain from appbase, SFC-encrypted with the chipkey. Each
#     entry's header is followed by its data; the next header sits `size` bytes on.
#       - dir (app_area_head): reconstructed from its inner table (app.bin, cfg_tool
#         + the VM/PRCT/BTIF reserved declarations)
#       - file / dir-blob: header + decrypted payload
#   * partitions (VM / key_mac): raw bytes overlaid at their target offset AFTER
#     encryption. Delete the file (or drop `data:`) to leave the region blank.
#
# CRCs are recomputed bottom-up (leaf headers finalised before the enclosing
# dir's data_crc), so edited file contents get correct CRCs automatically.
#
# NOTE: output is a raw flash image. Re-wrapping into .ufw/.fwsc is out of scope
#       (flash the raw image, or wrap it with the vendor tooling).
#

from jltech.crc import jl_crc16
from jltech.cipher import jl_enc_cipher, jl_sfc_cipher

from pathlib import Path
import struct
import argparse
import yaml

###############################################################################

ap = argparse.ArgumentParser(description='New-Firmware packer (inverse of fwunpack_newfw.py)')
ap.add_argument('input', type=Path,
                help='Unpack directory (containing fwpack.yaml) or the fwpack.yaml file itself')
ap.add_argument('output', type=Path, help='Output raw flash image')
args = ap.parse_args()

###############################################################################

def enc_keystream(n, key=0xFFFF):
    ks = bytearray(n)
    jl_enc_cipher(ks, 0, n, key)      # 0 ^ keystream == keystream
    return ks

def name_field(entry):
    """The 16-byte name field. Prefer the exact raw bytes; otherwise encode the
    readable name with the observed `name + 0x00 + 0xFF...` padding convention."""
    if entry.get('name_raw'):
        return bytes.fromhex(entry['name_raw'])[:16].ljust(16, b'\xFF')
    nb = entry['name'].encode('gb2312')[:16]
    return nb if len(nb) >= 16 else (nb + b'\x00' + b'\xFF' * (15 - len(nb)))

def put_header(buf, pos, entry, data_crc):
    """Pack a 32-byte JLFS entry [hcrc][30-byte hdr] at pos (decrypted domain)."""
    hdr = struct.pack('<HIIBBH16s', data_crc & 0xFFFF, entry['offset'] & 0xFFFFFFFF,
                      entry['size'] & 0xFFFFFFFF, entry['flags'] & 0xFF,
                      entry['resvd'] & 0xFF, entry['index'] & 0xFFFF, name_field(entry))
    struct.pack_into('<H30s', buf, pos, jl_crc16(hdr), hdr)

###############################################################################

def main():
    indir = args.input
    manifest_path = indir if indir.is_file() else indir / 'fwpack.yaml'
    indir = manifest_path.parent
    m = yaml.safe_load(open(manifest_path))

    if m.get('format') != 'jl-new-fw-pack':
        raise SystemExit(f'[!] not a jl-new-fw-pack manifest: {manifest_path}')

    base = m['base_offset']
    size = m['image_size']
    chipkey = m['chip_key']
    fh = m['flash_header']

    buf = bytearray(b'\xFF' * size)

    def rd(entry, key='file'):
        return (indir / entry[key]).read_bytes()

    def place(off, data, limit, what):
        """Write entry data at off, refusing to let it spill out of the region the
        manifest assigns to it (which would silently clobber whatever follows)."""
        if len(data) > limit:
            raise SystemExit(
                f'[!] {what}: {len(data)} bytes exceeds the {limit}-byte area assigned '
                f'to it by {len(data) - limit} bytes.\n'
                f'    Enlarge its `size` in the manifest and make room for it (shift the '
                f'following offsets / shrink the VM partition).')
        if off + len(data) > size:
            raise SystemExit(f'[!] {what} @ {off:#x}: runs {off + len(data) - size} bytes '
                             f'past the {size}-byte image end')
        buf[off:off+len(data)] = data

    # ---- flash header (vid/pid raw, CRC over the descrambled 32 bytes) ----
    ks = enc_keystream(32)
    L = bytearray(32)
    struct.pack_into('<HH4sIBBBB16s', L, 0,
                     0,                                   # crc placeholder
                     fh['burner_size'],
                     bytes.fromhex(fh['vid_hex']),        # placeholder, fixed below
                     fh['flash_size'], fh['fs_version'], fh['block_alignment'],
                     fh['reserved'], fh['special_option'],
                     bytes.fromhex(fh['pid_hex']))        # placeholder, fixed below
    # store vid/pid so that scrambling yields the raw bytes
    vid_raw = bytes.fromhex(fh['vid_hex'])
    pid_raw = bytes.fromhex(fh['pid_hex'])
    L[4:8]   = bytes(a ^ b for a, b in zip(vid_raw, ks[4:8]))
    L[16:32] = bytes(a ^ b for a, b in zip(pid_raw, ks[16:32]))
    struct.pack_into('<H', L, 0, jl_crc16(bytes(L[2:32])))
    jl_enc_cipher(L, 0, 32, 0xFFFF)                        # scramble -> on-flash form
    buf[base:base+32] = L

    # ---- top area ----
    appbase = None
    top = m['top']
    pos = base + 32
    for e in top:
        hdr_pos = pos
        pos += 32
        kind = e['kind']
        data_off = e['offset'] + base

        if kind == 'spl':
            data = rd(e)
            place(data_off, data, e['size'], f'top/{e["name"]}')
            data_crc = e['data_crc']              # over the DECODED spl; keep verbatim
        elif kind == 'plain':
            data = rd(e)
            place(data_off, data, e['size'], f'top/{e["name"]}')
            data_crc = jl_crc16(data)
        elif kind == 'app-area':
            appbase = e['offset'] + base
            data_crc = e['data_crc']              # 0xFFFF (declaration)
        elif kind == 'reserved':
            data_crc = e['data_crc']              # 0xFFFF (declaration)
        else:
            raise SystemExit(f'[!] unknown top kind "{kind}" for {e["name"]}')

        put_header(buf, hdr_pos, e, data_crc)
        jl_enc_cipher(buf, hdr_pos, 32, 0xFFFF)            # ENC-scramble the header

    if appbase is None:
        raise SystemExit('[!] no app-area (app_dir_head) entry in the manifest')

    # ---- app area (daisy chain, decrypted domain) ----
    partition_writes = []     # (abs_offset, bytes) applied after SFC encryption
    cursor = 0
    for e in m['app']:
        hdr_pos = appbase + cursor
        sizef = e['size']
        data_pos = hdr_pos + 32
        kind = e['kind']

        if kind == 'dir':
            # assemble the inner table + files inside [data_pos, hdr_pos+sizef)
            database = hdr_pos
            dir_end = hdr_pos + sizef
            ipos = hdr_pos + 32
            for a in e['inner']:
                # the inner header table itself has to fit in the directory
                if ipos + 32 > dir_end:
                    raise SystemExit(f'[!] {e["name"]}: the inner header table overflows '
                                     f'the {sizef}-byte directory at entry "{a["name"]}"')
                iflags = a['flags']
                if iflags & 0x10:
                    # reserved declaration: header only; queue its partition data.
                    # Its extent is a declaration (PRCT/VM reach outside the dir on
                    # purpose), so it gets no containment check here.
                    put_header(buf, ipos, a, a['data_crc'])
                    if 'data' in a:
                        partition_writes.append((a['offset'] + database, rd(a, 'data'), a['size']))
                else:
                    d_off = a['offset'] + database
                    what = f'{e["name"]}/{a["name"]}'
                    if d_off + a['size'] > dir_end:
                        raise SystemExit(
                            f'[!] {what}: its declared {a["size"]}-byte extent ends '
                            f'{d_off + a["size"] - dir_end} bytes past the {sizef}-byte '
                            f'directory "{e["name"]}" - enlarge the directory `size` too.')
                    place(d_off, rd(a), a['size'], what)
                    put_header(buf, ipos, a, jl_crc16(bytes(buf[d_off:d_off+a['size']])))
                ipos += 32
            block = bytes(buf[data_pos:dir_end])
            data_crc = jl_crc16(block)

        elif kind in ('file', 'dir-blob'):
            # `size` covers the 32-byte header + the payload
            place(data_pos, rd(e), sizef - 32, e['name'])
            data_crc = jl_crc16(bytes(buf[data_pos:hdr_pos + sizef]))

        else:
            raise SystemExit(f'[!] unknown app kind "{kind}" for {e["name"]}')

        put_header(buf, hdr_pos, e, data_crc)
        cursor += sizef

    sfc_end = appbase + cursor
    jl_sfc_cipher(buf, appbase, sfc_end - appbase, appbase, chipkey)

    # Overlay raw bytes (partitions, then raw regions) AFTER encryption, guarding
    # against two footguns: writing past the image end (never grow the buffer) and
    # clobbering the firmware [appbase, sfc_end) - which happens when app.bin has
    # grown into space a stale partition/raw region still claims.
    def overlay(off, data, what, limit=None):
        if limit is not None and len(data) > limit:
            print(f'[!] {what}: {len(data)} bytes exceeds its {limit}-byte region, truncated')
            data = data[:limit]
        if off + len(data) > len(buf):
            print(f'[!] {what}: runs {off + len(data) - len(buf)} bytes past image end, truncated')
            data = data[:len(buf) - off]
        if off < sfc_end and off + len(data) > appbase:
            print(f'[!] {what} @ {off:#x} OVERLAPS firmware [{appbase:#x},{sfc_end:#x}) - '
                  f'skipped (blank/move/shrink it, or it will corrupt the image)')
            return
        buf[off:off+len(data)] = data

    # ---- top-level reserved partitions (e.g. key_mac) ----
    for e in top:
        if e['kind'] == 'reserved' and 'data' in e:
            partition_writes.append((e['offset'] + base, rd(e, 'data'), e['size']))

    # app-area partitions first, then top ones (key_mac), so specific top slots win
    for off, data, region in partition_writes:
        overlay(off, data, 'partition', region)

    # ---- defensive raw regions (dead leftover bytes; usually none) ----
    for r in m.get('raw_regions', []) or []:
        overlay(r['offset'], (indir / r['file']).read_bytes(), f"raw region {r['file']}")

    del buf[size:]                      # never emit more than image_size
    args.output.write_bytes(buf)
    print(f'Packed: {args.output}  ({len(buf)} bytes)  appbase @ {appbase:#x}, '
          f'sfc_end @ {sfc_end:#x}, {len(partition_writes)} partition(s)')

main()
