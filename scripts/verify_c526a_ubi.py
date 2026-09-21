#!/usr/bin/env python3
"""Validate NAND geometry, UBI metadata and payloads of a C526A factory image.

CRC calibration for the known-good Run #16 factory image: EC PEB0 hdr_crc is
0xA66DDF45 and VID PEB2 hdr_crc is 0x73B1AB57.  UBI stores CRC-32 with the
final inversion omitted: ``binascii.crc32(bytes) ^ 0xffffffff``.  Header CRC
is at offset 60 over [0, 60); a volume-table record CRC is at 168 over
[0, 168).  Recalibrate these facts before changing or removing this check.
"""

import binascii
import pathlib
import struct
import sys


ERASE_BLOCK = 128 * 1024
NAND_SIZE = 128 * 1024 * 1024
VID_OFFSET = 2048
DATA_OFFSET = 4096
HEADER_CRC_LEN = 60
RECORD_SIZE = 172
RECORD_CRC_LEN = 168
AUTORESIZE_FLAG = 0x01000000
LAYOUT_VOL_ID = 0x7FFFEFFF
EXPECTED_VOLUMES = {0: "kernel", 1: "rootfs", 2: "rootfs_data"}
PAYLOAD_MAGIC = {0: b"\xd0\x0d\xfe\xed", 1: b"hsqs"}
MAGIC_NAME = {0: "FIT (d00dfeed)", 1: "squashfs (hsqs)"}


def u32(data, offset):
    return struct.unpack_from(">I", data, offset)[0]


def ubi_crc(data, offset, length):
    # UBI stores the standard CRC-32 result before its final inversion.
    return binascii.crc32(data[offset : offset + length]) ^ 0xFFFFFFFF


def check(path):
    image = pathlib.Path(path).read_bytes()
    if not image or len(image) % ERASE_BLOCK or len(image) > NAND_SIZE:
        raise ValueError("image size is empty, unaligned, or exceeds 128 MiB")

    image_seqs = set()
    lnum0 = {}
    per_volume = {}

    for peb in range(len(image) // ERASE_BLOCK):
        offset = peb * ERASE_BLOCK
        if image[offset : offset + 4] != b"UBI#":
            raise ValueError(f"PEB {peb}: missing UBI EC header")
        if u32(image, offset + 16) != VID_OFFSET or u32(image, offset + 20) != DATA_OFFSET:
            raise ValueError(f"PEB {peb}: VID/data offsets differ from 2048/4096")
        if ubi_crc(image, offset, HEADER_CRC_LEN) != u32(image, offset + 60):
            raise ValueError(f"PEB {peb}: EC header CRC mismatch")
        image_seqs.add(u32(image, offset + 24))

        vid = offset + VID_OFFSET
        if image[vid : vid + 4] != b"UBI!":
            raise ValueError(f"PEB {peb}: missing UBI VID header")
        if ubi_crc(image, vid, HEADER_CRC_LEN) != u32(image, vid + 60):
            raise ValueError(f"PEB {peb}: VID header CRC mismatch")

        vol_id = u32(image, vid + 8)
        lnum = u32(image, vid + 12)
        if vol_id != LAYOUT_VOL_ID:
            stats = per_volume.setdefault(vol_id, {"pebs": 0, "max_lnum": -1})
            stats["pebs"] += 1
            stats["max_lnum"] = max(stats["max_lnum"], lnum)
            if lnum == 0:
                lnum0[vol_id] = offset + DATA_OFFSET

    if len(image_seqs) != 1:
        raise ValueError(f"image_seq is not uniform: {sorted(image_seqs)}")

    for peb in (0, 1):
        vid = peb * ERASE_BLOCK + VID_OFFSET
        if u32(image, vid + 8) != LAYOUT_VOL_ID or u32(image, vid + 12) != peb:
            raise ValueError("first two PEBs are not the UBI layout volume")

    volumes = {}
    for vol_id in EXPECTED_VOLUMES:
        offset = DATA_OFFSET + vol_id * RECORD_SIZE
        if ubi_crc(image, offset, RECORD_CRC_LEN) != u32(image, offset + 168):
            raise ValueError(f"volume {vol_id}: volume table record CRC mismatch")
        reserved = u32(image, offset)
        volume_type = image[offset + 12]
        name_len = struct.unpack_from(">H", image, offset + 14)[0]
        if not 0 < reserved <= NAND_SIZE // ERASE_BLOCK or not 0 < name_len <= 128:
            raise ValueError(f"volume {vol_id}: invalid table record")
        if volume_type != 1:
            raise ValueError(f"volume {vol_id}: expected a dynamic UBI volume")
        volumes[vol_id] = image[offset + 16 : offset + 16 + name_len].decode("ascii")
    if volumes != EXPECTED_VOLUMES:
        raise ValueError(f"unexpected volume IDs/names: {volumes}")

    data_offset = DATA_OFFSET + 2 * RECORD_SIZE
    if u32(image, data_offset + 144) & AUTORESIZE_FLAG != AUTORESIZE_FLAG:
        raise ValueError("rootfs_data is not marked for automatic growth")

    for vol_id, magic in PAYLOAD_MAGIC.items():
        if vol_id not in lnum0:
            raise ValueError(f"volume {vol_id} ({EXPECTED_VOLUMES[vol_id]}): no LEB with lnum 0")
        start = lnum0[vol_id]
        if image[start : start + 4] != magic:
            raise ValueError(
                f"volume {vol_id} ({EXPECTED_VOLUMES[vol_id]}): lnum0 payload is not "
                f"{MAGIC_NAME[vol_id]} (first 4 bytes: {image[start:start+4].hex()})"
            )

    for vol_id in EXPECTED_VOLUMES:
        stats = per_volume.get(vol_id, {"pebs": 0, "max_lnum": -1})
        reserved = u32(image, DATA_OFFSET + vol_id * RECORD_SIZE)
        if vol_id != 2 and stats["pebs"] != reserved:
            print(
                f"note: volume {vol_id} ({EXPECTED_VOLUMES[vol_id]}): "
                f"{stats['pebs']} data PEBs vs reserved_pebs {reserved}",
                file=sys.stderr,
            )

    detail = ", ".join(
        f"{volumes[v]}={per_volume.get(v, {'pebs': 0})['pebs']}peb" for v in sorted(volumes)
    )
    print(
        f"OK: {path}: {len(image) // ERASE_BLOCK} PEBs, 128 KiB/2 KiB, "
        f"image_seq={image_seqs.pop()}, {detail}, "
        "header+table CRC verified, kernel=FIT, rootfs=squashfs, rootfs_data autogrow"
    )


if __name__ == "__main__":
    try:
        for filename in sys.argv[1:]:
            check(filename)
        if len(sys.argv) == 1:
            raise ValueError("factory.ubi path required")
    except (OSError, ValueError, struct.error) as error:
        print(f"UBI layout check failed: {error}", file=sys.stderr)
        sys.exit(1)

